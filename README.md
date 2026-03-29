# S3M NAC — Network Access Control Sistemi

RADIUS protokolü ile çalışan, Docker tabanlı ağ erişim kontrol sistemi.
PAP ve MAB doğrulama, VLAN atama, oturum takibi ve monitoring dashboard içerir.

## Mimari

```
Kullanıcı / Cihaz
       │
       │  RADIUS (UDP 1812/1813)
       ▼
┌──────────────────┐
│   FreeRADIUS 3.2 │
│   (rlm_rest)     │
└────────┬─────────┘
         │  HTTP POST (form-encoded)
         ▼
┌──────────────────┐
│  FastAPI Policy   │
│  Engine (8000)    │
└───┬──────────┬───┘
    │          │
    ▼          ▼
┌────────┐ ┌───────┐
│Postgres│ │ Redis │
│  (DB)  │ │(Cache)│
└────────┘ └───────┘
```

## Teknolojiler

| Servis | Teknoloji | Görev |
|--------|-----------|-------|
| freeradius | FreeRADIUS 3.2 | RADIUS sunucusu, rlm_rest ile API'ye sorar |
| api | Python 3.13 + FastAPI | Policy engine — auth, VLAN, accounting kararları |
| postgres | PostgreSQL 18 | Kullanıcılar, gruplar, VLAN politikaları, accounting |
| redis | Redis 8 | Aktif oturum cache, rate-limiting sayaçları |

## Hızlı Başlangıç

```bash
# 1. Repoyu klonla
git clone <repo-url>
cd s3m-nac

# 2. Environment dosyasını oluştur
cp .env.example .env

# 3. Sistemi başlat (ilk sefer build eder, 2-3 dk sürer)
docker-compose up -d --build

# 4. Servislerin hazır olduğunu kontrol et (hepsi healthy olmalı)
docker-compose ps

# 5. Testleri çalıştır (aşağıdaki Test bölümüne bak)
```

### Durdurma

```bash
# Durdur (veriler kalır)
docker-compose down

# Durdur + verileri sil (sıfırdan başlamak için)
docker-compose down -v
```

## Kullanıcılar (Seed Data)

| Kullanıcı | Şifre | Grup | VLAN |
|-----------|-------|------|------|
| admin1 | Admin.Pass.2026! | admin | 10 |
| employee1 | Emp.Pass.2026! | employee | 20 |
| employee2 | Emp2.Pass.2026! | employee | 20 |
| guest1 | Guest.Pass.2026! | guest | 30 |

Şifreler veritabanında bcrypt ile hashlenmiş olarak saklanır.

## MAC Cihazları (Seed Data)

| MAC Adresi | Cihaz | Tip | Grup | VLAN |
|------------|-------|-----|------|------|
| AA:BB:CC:DD:EE:01 | Kat-1 Yazıcı | printer | iot | 40 |
| AA:BB:CC:DD:EE:02 | Lobby IP Telefon | ip_phone | employee | 20 |
| AA:BB:CC:DD:EE:03 | Güvenlik Kamerası | camera | iot | 40 |
| AA:BB:CC:DD:EE:04 | Konferans Odası AP | access_point | admin | 10 |

Bilinmeyen MAC adresleri otomatik olarak guest grubuna düşer → VLAN 30.

## VLAN Politikaları

| Grup | VLAN | Filter | Açıklama |
|------|------|--------|----------|
| admin | 10 | admin-acl | Tam erişim |
| employee | 20 | employee-acl | İş uygulamaları |
| guest | 30 | guest-acl | Sadece internet (1 saat limit) |
| iot | 40 | iot-acl | Cihaz ağı, izole |

## API Endpoint'leri

| Endpoint | Metot | İşlev |
|----------|-------|-------|
| /health | GET | Sağlık kontrolü |
| /auth | POST | Authentication (PAP + MAB) |
| /authorize | POST | VLAN ve politika ataması |
| /accounting | POST | Oturum kaydı (Start/Update/Stop) |
| /users | GET | Kullanıcı listesi ve online durumu |
| /sessions/active | GET | Aktif oturumlar (Redis cache) |
| /devices | GET/POST | MAC cihaz listesi ve ekleme |
| /accounting/history | GET | Accounting geçmişi |
| /dashboard | GET | Monitoring dashboard (HTML) |
| /dashboard/data | GET | Dashboard JSON verisi |

## Test

### Ön Koşul

Tüm servisler healthy olmalı:
```bash
docker-compose ps
```

### Veritabanı Verilerini Görüntüleme

Testlerden önce DB'deki verileri kontrol etmek için:
```bash
# Kullanıcılar
docker exec nac-postgres psql -U nac_admin -d nac_db -c "SELECT username, attribute, substring(value,1,20) as value FROM radcheck;"

# Kullanıcı-grup eşleşmesi
docker exec nac-postgres psql -U nac_admin -d nac_db -c "SELECT username, groupname FROM radusergroup;"

# Grup VLAN politikaları
docker exec nac-postgres psql -U nac_admin -d nac_db -c "SELECT groupname, attribute, value FROM radgroupreply ORDER BY groupname;"

# MAC cihazları
docker exec nac-postgres psql -U nac_admin -d nac_db -c "SELECT mac_address, device_name, groupname FROM mac_devices;"
```

### PAP Authentication Testleri

```bash
# Başarılı giriş — admin1 (Accept + VLAN 10 bekleniyor)
docker exec nac-freeradius radtest admin1 "Admin.Pass.2026!" localhost 0 testing123

# Başarılı giriş — employee1 (Accept + VLAN 20 bekleniyor)
docker exec nac-freeradius radtest employee1 "Emp.Pass.2026!" localhost 0 testing123

# Hatalı şifre (Reject bekleniyor)
docker exec nac-freeradius radtest admin1 "yanlis" localhost 0 testing123
```

### MAB Authentication Testleri

```bash
# Kayıtlı cihaz — yazıcı (Accept bekleniyor)
docker exec nac-freeradius bash -c "echo 'User-Name=AA:BB:CC:DD:EE:01,User-Password=AA:BB:CC:DD:EE:01,Calling-Station-Id=AA:BB:CC:DD:EE:01' | radclient localhost auth testing123"

# Bilinmeyen cihaz (Accept + guest VLAN bekleniyor)
docker exec nac-freeradius bash -c "echo 'User-Name=FF:FF:FF:FF:FF:FF,User-Password=FF:FF:FF:FF:FF:FF,Calling-Station-Id=FF:FF:FF:FF:FF:FF' | radclient localhost auth testing123"
```

### API Endpoint Testleri

```bash
# Kullanıcı listesi (4 kullanıcı bekleniyor)
docker exec nac-freeradius curl -s http://nac-api:8000/users

# Cihaz listesi (4 cihaz bekleniyor)
docker exec nac-freeradius curl -s http://nac-api:8000/devices

# Aktif oturumlar (başlangıçta boş)
docker exec nac-freeradius curl -s http://nac-api:8000/sessions/active
```

### Accounting Testleri

```bash
# 1. Oturum başlat
docker exec nac-freeradius bash -c 'curl -s -X POST http://nac-api:8000/accounting -H "Content-Type: application/json" -d "{\"User-Name\":\"admin1\",\"Acct-Status-Type\":\"Start\",\"Acct-Session-Id\":\"sess-001\",\"Acct-Unique-Session-Id\":\"uniq001\",\"NAS-IP-Address\":\"172.20.0.1\",\"Framed-IP-Address\":\"10.0.10.5\"}"'

# 2. Aktif oturumları kontrol et (1 oturum olmalı)
docker exec nac-freeradius curl -s http://nac-api:8000/sessions/active

# 3. Oturumu kapat
docker exec nac-freeradius bash -c 'curl -s -X POST http://nac-api:8000/accounting -H "Content-Type: application/json" -d "{\"User-Name\":\"admin1\",\"Acct-Status-Type\":\"Stop\",\"Acct-Session-Id\":\"sess-001\",\"Acct-Session-Time\":\"300\",\"Acct-Terminate-Cause\":\"User-Request\"}"'

# 4. Accounting geçmişi (kayıt görünmeli)
docker exec nac-freeradius curl -s http://nac-api:8000/accounting/history
```

### Dashboard

```bash
# Dashboard JSON verisi
docker exec nac-freeradius curl -s http://nac-api:8000/dashboard/data
```

Tarayıcıdan görsel dashboard:
```
http://localhost:8000/dashboard
```

### Unit Testler

```bash
# 26 test çalıştır (hepsi PASSED olmalı)
docker exec nac-api pytest test_main.py -v
```

Test kapsamı:
- MAC normalizasyonu (6 test)
- MAB tespiti (6 test)
- bcrypt hashing (6 test)
- Health endpoint (1 test)
- Auth endpoint (6 test: başarılı, hatalı şifre, kullanıcı yok, şifresiz, kilitli, MAB)
- bcrypt ile auth (1 test)

## Güvenlik Önlemleri

- **bcrypt hashing** — şifreler düz metin saklanmaz
- **Rate limiting** — 5 başarısız deneme → 10 dk kilit (Redis)
- **Bilinmeyen MAC** — otomatik guest VLAN'a yönlendirme
- **.env** — secret'lar git'e commit edilmez
- **Docker network** — servisler izole bridge network'te
- **Healthcheck** — her serviste sağlık kontrolü aktif

## Proje Yapısı

```
s3m-nac/
├── docker-compose.yml            # 4 servis orkestrasyonu
├── .env.example                  # Ortam değişkenleri şablonu
├── .gitignore
├── README.md
├── api/
│   ├── Dockerfile                # FastAPI image
│   ├── requirements.txt          # Python bağımlılıkları
│   ├── main.py                   # Tüm endpoint'ler + dashboard
│   ├── database.py               # PostgreSQL + Redis bağlantıları
│   ├── models.py                 # Pydantic modelleri
│   └── test_main.py              # 26 unit test
├── db/
│   ├── init.sql                  # Veritabanı şeması (7 tablo)
│   └── seed.sql                  # Örnek veriler (bcrypt hash'li)
├── freeradius/
│   ├── Dockerfile                # FreeRADIUS + config kopyalama
│   ├── clients.conf              # RADIUS client tanımları
│   ├── mods-enabled/
│   │   └── rest                  # rlm_rest → FastAPI (body=post)
│   └── sites-enabled/
│       └── default               # Virtual server (auth/authz/acct)
└── scripts/
    ├── test_all.sh               # Toplu test scripti
    └── test_rate_limit.sh        # Rate limit testi
```