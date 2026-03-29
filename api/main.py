"""
NAC Policy Engine — FastAPI

FreeRADIUS rlm_rest modülü bu API'ye istek atıyor.
body = 'post' modunda form-encoded veri geliyor.
HTTP 200 dönersek accept, 401 dönersek reject oluyor.
Başarılı auth'ta boş body ({}) dönüyoruz yoksa rlm_rest
"updated" dönüp reject veriyor.
"""

# standart kütüphaneler
import json
import uuid
import logging
import bcrypt  # şifre hashleme için
from datetime import datetime
from contextlib import asynccontextmanager

# fastapi ve response tipleri
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse

# kendi yazdığım db ve redis bağlantı fonksiyonları
from database import get_pg_pool, get_redis, close_pg_pool, close_redis
# pydantic modelleri (UserInfo, MacDevice)
from models import UserInfo, MacDevice

# log formatını ayarlıyorum, her satırda zaman damgası ve seviye görünsün
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nac-api")

# rate limiting sabitleri
MAX_FAILED = 5       # kaç denemeden sonra kilitlensin
FAIL_WINDOW = 300    # başarısız denemeleri kaç saniye sayacak (5dk)
LOCKOUT_TIME = 600   # kilitlenince kaç saniye bekleyecek (10dk)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """uygulama açılırken db ve redis bağlantılarını kur, kapanırken kapat"""
    logger.info("NAC Policy Engine başlatılıyor...")
    await get_pg_pool()   # postgres connection pool oluştur
    get_redis()            # redis client oluştur
    logger.info("DB ve Redis bağlantıları hazır.")
    yield                  # uygulama burada çalışıyor
    # buradan sonrası kapanış
    await close_pg_pool()
    await close_redis()


# fastapi uygulamasını oluştur, lifespan ile başlangıç/kapanış bağla
app = FastAPI(
    title="NAC Policy Engine",
    description="Network Access Control — AAA",
    version="1.0.0",
    lifespan=lifespan,
)

# db verileri icin api erisimi
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════
# YARDIMCI FONKSİYONLAR
# ══════════════════════════════════════════════════════════════

def normalize_mac(mac: str) -> str:
    """gelen mac adresini AA:BB:CC:DD:EE:FF formatına çevir
    farklı formatlar olabiliyor: aa-bb-cc, aabb.ccdd, aabbccdd gibi"""
    # önce tüm ayraçları kaldır ve büyük harfe çevir
    clean = mac.replace("-", "").replace(":", "").replace(".", "").upper()
    # 12 karakter değilse geçersiz mac, olduğu gibi dön
    if len(clean) != 12:
        return mac.upper()
    # her 2 karakteri : ile birleştir
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))


def hash_password(plain: str) -> str:
    """düz metin şifreyi bcrypt ile hashle"""
    # gensalt() her seferinde farklı salt üretiyor
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """kullanıcının girdiği şifreyi db'deki hash ile karşılaştır"""
    # $2b$ veya $2a$ ile başlıyorsa bcrypt hash'i demek
    if hashed.startswith("$2b$") or hashed.startswith("$2a$"):
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    # hashli değilse düz metin karşılaştır (eski kayıtlar için geriye uyumluluk)
    return plain == hashed


async def is_mab_request(username: str) -> bool:
    """gelen username aslında mac adresi mi kontrol et
    12 hex karakter ise mac adresi olarak değerlendiriyoruz"""
    clean = username.replace("-", "").replace(":", "").replace(".", "")
    return len(clean) == 12 and all(c in "0123456789ABCDEFabcdef" for c in clean)


async def check_rate_limit(username: str) -> tuple[bool, int]:
    """redis'te bu kullanıcı kilitli mi bak"""
    rd = get_redis()
    lock_key = f"lock:{username}"
    # lock key varsa kullanıcı kilitli, kalan süreyi dön
    if await rd.exists(lock_key):
        return True, await rd.ttl(lock_key)
    # kilitli değilse kaç başarısız deneme var onu bul
    attempts = await rd.get(f"fail:{username}")
    current = int(attempts) if attempts else 0
    # kalan hakkı hesapla
    return False, MAX_FAILED - current


async def record_failed(username: str):
    """başarısız giriş denemesini redis'e kaydet"""
    rd = get_redis()
    # sayacı 1 artır (yoksa oluşturur)
    count = await rd.incr(f"fail:{username}")
    # 5 dakika ttl koy, eski denemeler otomatik silinsin
    await rd.expire(f"fail:{username}", FAIL_WINDOW)
    # limite ulaştıysa hesabı kilitle
    if count >= MAX_FAILED:
        # 10 dakika lock koy
        await rd.setex(f"lock:{username}", LOCKOUT_TIME, "1")
        # sayacı sıfırla artık gerek yok
        await rd.delete(f"fail:{username}")
        logger.warning(f"Kullanıcı kilitlendi: {username}")


async def clear_failed(username: str):
    """başarılı girişte sayacı sıfırla"""
    await get_redis().delete(f"fail:{username}")


def serialize_row(row) -> dict:
    """db'den gelen satırı json'a çevirebilir hale getir
    datetime objeleri json.dumps yapamaz o yüzden isoformat'a çeviriyorum"""
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


async def parse_body(request: Request) -> dict:
    """gelen isteğin body'sini parse et
    freeradius form-encoded gönderiyor, curl json gönderiyor
    ikisini de desteklememiz lazım"""
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        # curl veya postman'den json geldi
        return await request.json()
    elif "application/x-www-form-urlencoded" in content_type:
        # freeradius rlm_rest'ten form data geldi
        form = await request.form()
        return dict(form)
    else:
        # content-type belirsiz, önce json dene
        body_bytes = await request.body()
        try:
            return json.loads(body_bytes)
        except (json.JSONDecodeError, ValueError):
            # json değilse form olarak dene
            form = await request.form()
            return dict(form)


# ══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    """docker healthcheck bu endpoint'i kontrol ediyor"""
    return {"status": "healthy", "service": "nac-policy-engine"}


# ══════════════════════════════════════════════════════════════
# 1. AUTH — POST /auth
# freeradius authenticate bölümünde buraya istek atıyor
# 200 dönersek accept, 401 dönersek reject
# ══════════════════════════════════════════════════════════════

@app.post("/auth")
async def authenticate(request: Request):
    """kullanıcı doğrulama — hem PAP hem MAB burada"""
    body = await parse_body(request)
    logger.info(f"Auth: {body}")

    # radius attribute isimleriyle geliyor
    username = body.get("User-Name", "")
    password = body.get("User-Password", "")

    # önce rate limit kontrolü, kilitliyse direkt reddet
    locked, info = await check_rate_limit(username)
    if locked:
        logger.warning(f"Rate limit: {username} kilitli ({info}s)")
        return JSONResponse(status_code=401, content={
            "Reply-Message": f"Hesap kilitli. {info}s sonra deneyin."
        })

    pool = await get_pg_pool()

    # username mac formatında mı? öyleyse MAB akışına gir
    if await is_mab_request(username):
        mac = normalize_mac(username)
        logger.info(f"MAB: {mac}")
        # mac_devices tablosunda bu adres kayıtlı mı
        device = await pool.fetchrow(
            "SELECT * FROM mac_devices WHERE mac_address = $1 AND is_active = TRUE", mac
        )
        if device:
            logger.info(f"MAB OK: {mac} → {device['groupname']}")
            # boş body dön → rlm_rest "ok" döner → accept
            # vlan ataması authorize'da zaten yapıldı
            return JSONResponse(status_code=200, content={})
        else:
            # bilinmeyen mac → yine accept ama authorize'da guest vlan'a düşecek
            logger.info(f"MAB bilinmeyen: {mac} → guest")
            return JSONResponse(status_code=200, content={})

    # buraya geldiyse normal kullanıcı, PAP doğrulama yapacağız
    if not password:
        return JSONResponse(status_code=401, content={
            "Reply-Message": "Şifre gerekli."
        })

    # radcheck tablosundan kullanıcının hashli şifresini çek
    row = await pool.fetchrow(
        "SELECT value FROM radcheck WHERE username = $1 AND attribute = 'Cleartext-Password'",
        username
    )
    if not row:
        # kullanıcı yok, başarısız deneme olarak kaydet
        await record_failed(username)
        return JSONResponse(status_code=401, content={
            "Reply-Message": "Kullanıcı bulunamadı."
        })

    # bcrypt ile şifre karşılaştır
    if not verify_password(password, row["value"]):
        await record_failed(username)
        return JSONResponse(status_code=401, content={
            "Reply-Message": "Hatalı şifre."
        })

    # buraya geldiyse şifre doğru, sayacı sıfırla
    await clear_failed(username)
    logger.info(f"Auth OK: {username}")
    # ÖNEMLİ: boş body dönüyoruz
    # body'de veri olursa rlm_rest attribute günceller → "updated" döner
    # "updated" freeradius'ta reject demek, "ok" ise accept
    return JSONResponse(status_code=200, content={})


# ══════════════════════════════════════════════════════════════
# 2. AUTHORIZE — POST /authorize
# freeradius authorize bölümünde buraya istek atıyor
# kullanıcının grubunu bulup vlan attribute'lerini dönüyoruz
# ══════════════════════════════════════════════════════════════

@app.post("/authorize")
async def authorize(request: Request):
    """yetkilendirme — gruba göre vlan ve politika ata"""
    body = await parse_body(request)
    logger.info(f"Authorize: {body}")

    username = body.get("User-Name", "")
    pool = await get_pg_pool()

    # mac adresi mi yoksa normal kullanıcı mı
    if await is_mab_request(username):
        mac = normalize_mac(username)
        # mac_devices tablosundan cihazın grubunu bul
        device = await pool.fetchrow(
            "SELECT groupname FROM mac_devices WHERE mac_address = $1 AND is_active = TRUE", mac
        )
        # kayıtlı değilse guest grubuna düşür
        groupname = device["groupname"] if device else "guest"
    else:
        # normal kullanıcı, radusergroup tablosundan grubunu bul
        row = await pool.fetchrow(
            "SELECT groupname FROM radusergroup WHERE username = $1 ORDER BY priority LIMIT 1",
            username
        )
        groupname = row["groupname"] if row else "guest"

    # bu grubun vlan ve politika attribute'lerini çek
    attrs = await pool.fetch(
        "SELECT attribute, value FROM radgroupreply WHERE groupname = $1", groupname
    )
    # kullanıcıya özel ek attribute varsa onları da al
    user_attrs = await pool.fetch(
        "SELECT attribute, value FROM radreply WHERE username = $1", username
    )

    # hepsini bir dict'e topla
    result = {}
    for r in attrs:
        result[r["attribute"]] = r["value"]
    for r in user_attrs:
        result[r["attribute"]] = r["value"]

    logger.info(f"Authorize: {username} → {groupname} → {result}")
    # burada dolu body dönüyoruz, authorize'da sorun yok
    # freeradius bu attribute'leri reply paketine ekliyor (vlan vs)
    return result


# ══════════════════════════════════════════════════════════════
# 3. ACCOUNTING — POST /accounting
# oturum verilerini kaydet: start, interim-update, stop
# postgresql'e yaz + redis'te cache'le
# ══════════════════════════════════════════════════════════════

@app.post("/accounting")
async def accounting(request: Request):
    """oturum kayıtlarını işle"""
    body = await parse_body(request)
    logger.info(f"Acct: {body}")

    # radius accounting attribute'lerini al
    username = body.get("User-Name", "")
    status_type = body.get("Acct-Status-Type", "")  # Start, Interim-Update, Stop
    session_id = body.get("Acct-Session-Id", "")
    unique_id = body.get("Acct-Unique-Session-Id", uuid.uuid4().hex[:32])
    nas_ip = body.get("NAS-IP-Address", "")
    nas_port_id = body.get("NAS-Port-Id", "")
    # bunlar string geliyor, int'e çeviriyorum
    session_time = int(body.get("Acct-Session-Time", 0) or 0)
    input_octets = int(body.get("Acct-Input-Octets", 0) or 0)
    output_octets = int(body.get("Acct-Output-Octets", 0) or 0)
    terminate_cause = body.get("Acct-Terminate-Cause", "")
    framed_ip = body.get("Framed-IP-Address", "")
    calling_station = body.get("Calling-Station-Id", "")
    called_station = body.get("Called-Station-Id", "")

    pool = await get_pg_pool()
    rd = get_redis()
    # utcnow kullanıyorum, timezone-aware datetime asyncpg'de hata veriyor
    now = datetime.utcnow()
    skey = f"session:{session_id}"  # redis'teki cache key'i

    if status_type == "Start":
        # yeni oturum başladı, radacct tablosuna kaydet
        await pool.execute("""
            INSERT INTO radacct (acctsessionid, acctuniqueid, username, nasipaddress,
                nasportid, acctstarttime, acctupdatetime, framedipaddress,
                callingstationid, calledstationid)
            VALUES ($1,$2,$3,$4,$5,$6,$6,$7,$8,$9)
            ON CONFLICT (acctuniqueid) DO NOTHING
        """, session_id, unique_id, username, nas_ip, nas_port_id,
            now, framed_ip, calling_station, called_station)
        # ON CONFLICT → aynı paket tekrar gelirse hata vermez, sessizce atlar

        # redis'e cache olarak kaydet, 24 saat ttl
        await rd.setex(skey, 86400, json.dumps({
            "username": username, "session_id": session_id,
            "nas_ip": nas_ip, "framed_ip": framed_ip,
            "start_time": now.isoformat(),
            "session_time": 0, "input_octets": 0, "output_octets": 0,
        }))
        # kullanıcının aktif oturum listesine ekle (set yapısı, duplicate yok)
        await rd.sadd(f"user_sessions:{username}", session_id)
        logger.info(f"Acct START: {username} sess={session_id}")

    elif status_type == "Interim-Update":
        # periyodik güncelleme, süre ve veri miktarını güncelle
        await pool.execute("""
            UPDATE radacct SET acctupdatetime=$1, acctsessiontime=$2,
                acctinputoctets=$3, acctoutputoctets=$4, framedipaddress=$5
            WHERE acctsessionid=$6 AND acctstoptime IS NULL
        """, now, session_time, input_octets, output_octets, framed_ip, session_id)

        # redis cache'i de güncelle
        cached = await rd.get(skey)
        if cached:
            sd = json.loads(cached)
            sd.update(session_time=session_time, input_octets=input_octets,
                      output_octets=output_octets, framed_ip=framed_ip)
            await rd.setex(skey, 86400, json.dumps(sd))
        logger.info(f"Acct UPDATE: {username} sess={session_id}")

    elif status_type == "Stop":
        # oturum bitti, bitiş zamanı ve sebebi kaydet
        await pool.execute("""
            UPDATE radacct SET acctstoptime=$1, acctupdatetime=$1,
                acctsessiontime=$2, acctinputoctets=$3, acctoutputoctets=$4,
                acctterminatecause=$5
            WHERE acctsessionid=$6 AND acctstoptime IS NULL
        """, now, session_time, input_octets, output_octets, terminate_cause, session_id)

        # redis'ten sil, artık aktif değil
        await rd.delete(skey)
        await rd.srem(f"user_sessions:{username}", session_id)
        logger.info(f"Acct STOP: {username} sess={session_id}")

    return {"Reply-Message": f"Accounting {status_type} OK"}


# ══════════════════════════════════════════════════════════════
# 4. GET /users — kullanıcı listesi
# her kullanıcının grubu, vlan'ı ve online durumu
# ══════════════════════════════════════════════════════════════

@app.get("/users")
async def list_users():
    """tüm kullanıcıları listele"""
    pool = await get_pg_pool()
    rd = get_redis()
    # radcheck + radusergroup + radgroupreply join'leyerek
    # kullanıcı, grup ve vlan bilgisini tek sorguda çekiyorum
    rows = await pool.fetch("""
        SELECT rc.username, COALESCE(rug.groupname, 'ungrouped') AS groupname,
            (SELECT value FROM radgroupreply
             WHERE groupname = rug.groupname AND attribute = 'Tunnel-Private-Group-Id'
             LIMIT 1) AS vlan
        FROM radcheck rc
        LEFT JOIN radusergroup rug ON rc.username = rug.username
        WHERE rc.attribute = 'Cleartext-Password'
        ORDER BY rc.username
    """)
    users = []
    for r in rows:
        # redis'te bu kullanıcının aktif oturumu var mı
        sessions = await rd.smembers(f"user_sessions:{r['username']}")
        users.append(UserInfo(
            username=r["username"], group=r["groupname"],
            vlan=r["vlan"], is_online=len(sessions) > 0
        ).model_dump())
    return {"users": users, "total": len(users)}


# ══════════════════════════════════════════════════════════════
# 5. GET /sessions/active — aktif oturumlar (redis'ten)
# ══════════════════════════════════════════════════════════════

@app.get("/sessions/active")
async def active_sessions():
    """redis'teki tüm aktif oturumları listele"""
    rd = get_redis()
    sessions = []
    # session:* pattern'ine uyan tüm key'leri tara
    async for key in rd.scan_iter(match="session:*"):
        data = await rd.get(key)
        if data:
            sessions.append(json.loads(data))
    return {"sessions": sessions, "total": len(sessions)}


# ══════════════════════════════════════════════════════════════
# 6. MAC CİHAZ YÖNETİMİ — GET/POST /devices
# ══════════════════════════════════════════════════════════════

@app.get("/devices")
async def list_devices():
    """kayıtlı mac cihazlarını listele"""
    pool = await get_pg_pool()
    rows = await pool.fetch("SELECT * FROM mac_devices ORDER BY created_at DESC")
    return {"devices": [serialize_row(r) for r in rows], "total": len(rows)}


@app.post("/devices")
async def add_device(device: MacDevice):
    """yeni mac cihaz ekle"""
    pool = await get_pg_pool()
    mac = normalize_mac(device.mac_address)
    try:
        await pool.execute("""
            INSERT INTO mac_devices (mac_address, device_name, device_type, groupname, is_active)
            VALUES ($1,$2,$3,$4,$5)
        """, mac, device.device_name, device.device_type, device.groupname, device.is_active)
    except Exception as e:
        # büyük ihtimalle duplicate mac hatası
        raise HTTPException(status_code=400, detail=str(e))
    return {"message": f"Cihaz eklendi: {mac}"}


# ══════════════════════════════════════════════════════════════
# 7. GET /accounting/history — accounting geçmişi
# ══════════════════════════════════════════════════════════════

@app.get("/accounting/history")
async def accounting_history(username: str | None = None, limit: int = 50):
    """accounting kayıtlarını sorgula, opsiyonel kullanıcı filtresi"""
    pool = await get_pg_pool()
    if username:
        rows = await pool.fetch(
            "SELECT * FROM radacct WHERE username=$1 ORDER BY acctstarttime DESC LIMIT $2",
            username, limit)
    else:
        rows = await pool.fetch(
            "SELECT * FROM radacct ORDER BY acctstarttime DESC LIMIT $1", limit)
    return {"records": [serialize_row(r) for r in rows], "total": len(rows)}


# ══════════════════════════════════════════════════════════════
# 8. MONITORING DASHBOARD
# /dashboard/data → json veri, /dashboard → html sayfa
# bonus olarak ekledim, 10 saniyede bir otomatik yenileniyor
# ══════════════════════════════════════════════════════════════

@app.get("/dashboard/data")
async def dashboard_data():
    """dashboard için özet istatistikler"""
    pool = await get_pg_pool()
    rd = get_redis()

    # toplam kayıtlı kullanıcı sayısı
    user_count = await pool.fetchval(
        "SELECT COUNT(DISTINCT username) FROM radcheck WHERE attribute = 'Cleartext-Password'"
    )

    # aktif mac cihaz sayısı
    device_count = await pool.fetchval("SELECT COUNT(*) FROM mac_devices WHERE is_active = TRUE")

    # redis'teki aktif oturum sayısını say
    active_count = 0
    async for _ in rd.scan_iter(match="session:*"):
        active_count += 1

    # toplam accounting kaydı
    acct_count = await pool.fetchval("SELECT COUNT(*) FROM radacct")

    # son 24 saatte kaç oturum başlamış
    recent_sessions = await pool.fetchval("""
        SELECT COUNT(*) FROM radacct
        WHERE acctstarttime > NOW() - INTERVAL '24 hours'
    """)

    # şu an kaç hesap kilitli (redis'te lock:* key'leri)
    locked_count = 0
    async for _ in rd.scan_iter(match="lock:*"):
        locked_count += 1

    # hangi grupta kaç kullanıcı var
    group_dist = await pool.fetch("""
        SELECT groupname, COUNT(*) as count
        FROM radusergroup GROUP BY groupname ORDER BY count DESC
    """)

    # son 10 oturum kaydı
    recent_acct = await pool.fetch(
        "SELECT username, acctsessionid, acctstarttime, acctstoptime, acctsessiontime FROM radacct ORDER BY acctstarttime DESC LIMIT 10"
    )

    return {
        "summary": {
            "total_users": user_count,
            "total_devices": device_count,
            "active_sessions": active_count,
            "total_accounting_records": acct_count,
            "sessions_last_24h": recent_sessions,
            "locked_users": locked_count,
        },
        "group_distribution": [dict(r) for r in group_dist],
        "recent_activity": [serialize_row(r) for r in recent_acct],
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    """tarayıcıdan açılan monitoring sayfası
    javascript ile /dashboard/data'dan veri çekip gösteriyor
    10 saniyede bir otomatik yenileniyor"""
    return """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NAC Monitoring Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; padding: 20px; }
h1 { font-size: 22px; font-weight: 500; margin-bottom: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: #fff; border-radius: 12px; padding: 20px; border: 1px solid #e0e0e0; }
.card .label { font-size: 13px; color: #888; margin-bottom: 4px; }
.card .value { font-size: 28px; font-weight: 500; }
.card .value.green { color: #1d9e75; }
.card .value.blue { color: #378add; }
.card .value.red { color: #e24b4a; }
.card .value.amber { color: #ba7517; }
h2 { font-size: 17px; font-weight: 500; margin: 24px 0 12px; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; border: 1px solid #e0e0e0; }
th, td { padding: 10px 14px; text-align: left; font-size: 14px; border-bottom: 1px solid #f0f0f0; }
th { background: #fafafa; font-weight: 500; color: #666; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 500; }
.badge.active { background: #e1f5ee; color: #0f6e56; }
.badge.closed { background: #f1efe8; color: #5f5e5a; }
.refresh { background: none; border: 1px solid #ddd; padding: 6px 16px; border-radius: 8px; cursor: pointer; font-size: 13px; }
.refresh:hover { background: #f0f0f0; }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
</style>
</head>
<body>
<div class="header">
    <h1>NAC monitoring dashboard</h1>
    <button class="refresh" onclick="loadData()">Yenile</button>
</div>
<div class="grid" id="cards"></div>
<h2>Grup dagilimi</h2>
<table id="groups"><tr><th>Grup</th><th>Kullanici sayisi</th></tr></table>
<h2>Son aktiviteler</h2>
<table id="activity"><tr><th>Kullanici</th><th>Oturum ID</th><th>Baslangic</th><th>Durum</th><th>Sure (sn)</th></tr></table>

<script>
async function loadData() {
    const res = await fetch('/dashboard/data');
    const data = await res.json();
    const s = data.summary;
    document.getElementById('cards').innerHTML =
        card('Toplam kullanici', s.total_users, 'blue') +
        card('Kayitli cihaz', s.total_devices, 'blue') +
        card('Aktif oturum', s.active_sessions, 'green') +
        card('Son 24 saat', s.sessions_last_24h, 'amber') +
        card('Kilitli hesap', s.locked_users, 'red') +
        card('Toplam kayit', s.total_accounting_records, 'blue');

    const gt = document.getElementById('groups');
    gt.innerHTML = '<tr><th>Grup</th><th>Kullanici sayisi</th></tr>';
    data.group_distribution.forEach(g => {
        gt.innerHTML += '<tr><td>' + g.groupname + '</td><td>' + g.count + '</td></tr>';
    });

    const at = document.getElementById('activity');
    at.innerHTML = '<tr><th>Kullanici</th><th>Oturum ID</th><th>Baslangic</th><th>Durum</th><th>Sure (sn)</th></tr>';
    data.recent_activity.forEach(a => {
        const status = a.acctstoptime ? '<span class="badge closed">kapali</span>' : '<span class="badge active">aktif</span>';
        const time = a.acctstarttime ? new Date(a.acctstarttime).toLocaleString('tr-TR') : '-';
        at.innerHTML += '<tr><td>' + a.username + '</td><td>' + (a.acctsessionid||'-') + '</td><td>' + time + '</td><td>' + status + '</td><td>' + (a.acctsessiontime||0) + '</td></tr>';
    });
}
function card(label, value, color) {
    return '<div class="card"><div class="label">' + label + '</div><div class="value ' + color + '">' + value + '</div></div>';
}
// sayfa yüklenince veri çek
loadData();
// 10 saniyede bir otomatik yenile
setInterval(loadData, 10000);
</script>
</body>
</html>"""