"""
NAC Policy Engine — Unit Tests

pytest ile çalıştır:
  docker exec nac-api pytest test_main.py -v
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient, ASGITransport
from main import app, normalize_mac, is_mab_request, hash_password, verify_password


# ══════════════════════════════════════════════════════════════
# 1. YARDIMCI FONKSİYON TESTLERİ
# ══════════════════════════════════════════════════════════════

class TestNormalizeMac:
    def test_colon_format(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_dash_format(self):
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_dot_format(self):
        assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"

    def test_no_separator(self):
        assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    def test_invalid_length(self):
        assert normalize_mac("aabb") == "AABB"

    def test_mixed_case(self):
        assert normalize_mac("Aa:Bb:Cc:Dd:Ee:Ff") == "AA:BB:CC:DD:EE:FF"


class TestIsMabRequest:
    @pytest.mark.asyncio
    async def test_mac_with_colons(self):
        assert await is_mab_request("AA:BB:CC:DD:EE:FF") is True

    @pytest.mark.asyncio
    async def test_mac_with_dashes(self):
        assert await is_mab_request("AA-BB-CC-DD-EE-FF") is True

    @pytest.mark.asyncio
    async def test_mac_no_separator(self):
        assert await is_mab_request("AABBCCDDEEFF") is True

    @pytest.mark.asyncio
    async def test_username_not_mac(self):
        assert await is_mab_request("admin1") is False

    @pytest.mark.asyncio
    async def test_short_string(self):
        assert await is_mab_request("abc") is False

    @pytest.mark.asyncio
    async def test_invalid_hex(self):
        assert await is_mab_request("GGHHIIJJKKLL") is False


# ══════════════════════════════════════════════════════════════
# 2. PASSWORD HASHING TESTLERİ
# ══════════════════════════════════════════════════════════════

class TestPasswordHashing:
    def test_hash_produces_bcrypt(self):
        h = hash_password("test123")
        assert h.startswith("$2b$")

    def test_verify_correct_password(self):
        h = hash_password("MySecret!")
        assert verify_password("MySecret!", h) is True

    def test_verify_wrong_password(self):
        h = hash_password("MySecret!")
        assert verify_password("WrongPass", h) is False

    def test_verify_plaintext_fallback(self):
        """Eski düz metin şifreler için geriye dönük uyumluluk."""
        assert verify_password("Admin.Pass.2026!", "Admin.Pass.2026!") is True

    def test_verify_plaintext_wrong(self):
        assert verify_password("wrong", "Admin.Pass.2026!") is False

    def test_different_hashes_same_password(self):
        """Aynı şifre farklı salt ile farklı hash üretmeli."""
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2
        assert verify_password("same", h1) is True
        assert verify_password("same", h2) is True


# ══════════════════════════════════════════════════════════════
# 3. API ENDPOINT TESTLERİ (mock DB/Redis)
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_pool():
    pool = AsyncMock()
    return pool


@pytest.fixture
def mock_redis():
    rd = AsyncMock()
    rd.exists = AsyncMock(return_value=False)
    rd.get = AsyncMock(return_value=None)
    rd.smembers = AsyncMock(return_value=set())
    return rd


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("main.get_pg_pool") as mock_pg, \
                 patch("main.get_redis") as mock_rd:
                mock_pg.return_value = AsyncMock()
                mock_rd.return_value = AsyncMock()
                resp = await client.get("/health")
                assert resp.status_code == 200
                data = resp.json()
                assert data["status"] == "healthy"


class TestAuthEndpoint:
    @pytest.mark.asyncio
    async def test_auth_success(self):
        """Doğru şifre ile 200 dönmeli."""
        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value={"value": "Admin.Pass.2026!"})
        mock_rd = AsyncMock()
        mock_rd.exists = AsyncMock(return_value=False)
        mock_rd.get = AsyncMock(return_value=None)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("main.get_pg_pool", return_value=mock_pool), \
                 patch("main.get_redis", return_value=mock_rd):
                resp = await client.post("/auth", json={
                    "User-Name": "admin1",
                    "User-Password": "Admin.Pass.2026!"
                })
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_auth_wrong_password(self):
        """Yanlış şifre ile 401 dönmeli."""
        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value={"value": "Admin.Pass.2026!"})
        mock_rd = AsyncMock()
        mock_rd.exists = AsyncMock(return_value=False)
        mock_rd.get = AsyncMock(return_value=None)
        mock_rd.incr = AsyncMock(return_value=1)
        mock_rd.expire = AsyncMock()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("main.get_pg_pool", return_value=mock_pool), \
                 patch("main.get_redis", return_value=mock_rd):
                resp = await client.post("/auth", json={
                    "User-Name": "admin1",
                    "User-Password": "yanlis_sifre"
                })
                assert resp.status_code == 401
                assert "Hatalı" in resp.json()["Reply-Message"]

    @pytest.mark.asyncio
    async def test_auth_user_not_found(self):
        """Olmayan kullanıcı ile 401 dönmeli."""
        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value=None)
        mock_rd = AsyncMock()
        mock_rd.exists = AsyncMock(return_value=False)
        mock_rd.get = AsyncMock(return_value=None)
        mock_rd.incr = AsyncMock(return_value=1)
        mock_rd.expire = AsyncMock()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("main.get_pg_pool", return_value=mock_pool), \
                 patch("main.get_redis", return_value=mock_rd):
                resp = await client.post("/auth", json={
                    "User-Name": "nobody",
                    "User-Password": "test"
                })
                assert resp.status_code == 401
                assert "bulunamadı" in resp.json()["Reply-Message"]

    @pytest.mark.asyncio
    async def test_auth_no_password(self):
        """Şifresiz istek 401 dönmeli."""
        mock_rd = AsyncMock()
        mock_rd.exists = AsyncMock(return_value=False)
        mock_rd.get = AsyncMock(return_value=None)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("main.get_pg_pool", return_value=AsyncMock()), \
                 patch("main.get_redis", return_value=mock_rd):
                resp = await client.post("/auth", json={
                    "User-Name": "admin1"
                })
                assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_auth_rate_limited(self):
        """Kilitli kullanıcı 401 dönmeli."""
        mock_rd = AsyncMock()
        mock_rd.exists = AsyncMock(return_value=True)
        mock_rd.ttl = AsyncMock(return_value=500)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("main.get_pg_pool", return_value=AsyncMock()), \
                 patch("main.get_redis", return_value=mock_rd):
                resp = await client.post("/auth", json={
                    "User-Name": "admin1",
                    "User-Password": "test"
                })
                assert resp.status_code == 401
                assert "kilitli" in resp.json()["Reply-Message"]

    @pytest.mark.asyncio
    async def test_auth_mab_known_device(self):
        """Kayıtlı MAC adresi 200 dönmeli."""
        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value={
            "mac_address": "AA:BB:CC:DD:EE:01",
            "device_name": "Yazici",
            "groupname": "iot",
            "is_active": True,
        })
        mock_rd = AsyncMock()
        mock_rd.exists = AsyncMock(return_value=False)
        mock_rd.get = AsyncMock(return_value=None)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("main.get_pg_pool", return_value=mock_pool), \
                 patch("main.get_redis", return_value=mock_rd):
                resp = await client.post("/auth", json={
                    "User-Name": "AA:BB:CC:DD:EE:01",
                    "User-Password": "AA:BB:CC:DD:EE:01"
                })
                assert resp.status_code == 200


class TestAuthBcrypt:
    @pytest.mark.asyncio
    async def test_auth_with_bcrypt_hash(self):
        """Bcrypt hashlenmiş şifre ile doğrulama."""
        hashed = hash_password("SecurePass!")
        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value={"value": hashed})
        mock_rd = AsyncMock()
        mock_rd.exists = AsyncMock(return_value=False)
        mock_rd.get = AsyncMock(return_value=None)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("main.get_pg_pool", return_value=mock_pool), \
                 patch("main.get_redis", return_value=mock_rd):
                resp = await client.post("/auth", json={
                    "User-Name": "testuser",
                    "User-Password": "SecurePass!"
                })
                assert resp.status_code == 200
