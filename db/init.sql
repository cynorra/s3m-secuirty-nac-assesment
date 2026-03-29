CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- pgcrypto - hashleme icin

-- ============================================================
-- RADCHECK
-- Kullanıcı kimlik doğrulama KOŞULLARINI tutar.
-- FreeRADIUS buradaki attribute/value çiftlerini kontrol eder.
-- Örnek satır:
--   username='ali', attribute='Cleartext-Password', op=':=', value='1234'
-- ============================================================

CREATE TABLE IF NOT EXISTS radcheck (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    attribute VARCHAR(64) NOT NULL, -- -- RADIUS attribute (ör. Cleartext-Password)
    op CHAR(2) NOT NULL DEFAULT ':=', 
    value VARCHAR(253) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_radcheck_username ON radcheck(username);
-- ^ Kullanıcı adına göre hızlı arama için index (auth sırasında sık sorgulanır)

-- ============================================================
-- RADREPLY
-- Kullanıcıya verilecek RADIUS ATTRIBUTE'lerini tutar.
-- Örnek satır:
--   username='ali', attribute='Tunnel-Private-Group-ID', op=':=', value='10'
-- ============================================================

CREATE TABLE IF NOT EXISTS radreply (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    attribute VARCHAR(64) NOT NULL,
    op CHAR(2) NOT NULL DEFAULT ':=',
    value VARCHAR(253) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_radreply_username ON radreply(username);
-- ^ Kullanıcıya verilecek attribute'leri tutar (VLAN, Session-Timeout vb.)

-- ============================================================
-- RADUSERGROUP
-- Kullanıcının hangi gruba bağlı olduğunu tutar.
-- FreeRADIUS bu tabloya bakarak hangi policy'nin uygulanacağını belirler.
-- Örnek satır:
--   username='ali', groupname='students', priority=1
-- ============================================================

CREATE TABLE IF NOT EXISTS radusergroup (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    groupname VARCHAR(64) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_radusergroup_username ON radusergroup(username);
-- ^ Kullanıcıların üye olduğu grupları tutar

-- ============================================================
-- RADGROUPREPLY
-- Gruplara verilecek RADIUS ATTRIBUTE'lerini tutar.
-- Örnek satır:
--   groupname='students', attribute='Tunnel-Private-Group-ID', op=':=', value='10'
-- ============================================================

CREATE TABLE IF NOT EXISTS radgroupreply (
    id SERIAL PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL,
    attribute VARCHAR(64) NOT NULL,
    op CHAR(2) NOT NULL DEFAULT ':=',
    value VARCHAR(253) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_radgroupreply_groupname ON radgroupreply(groupname);
-- ^ Gruplara verilecek attribute'leri tutar (VLAN, Session-Timeout vb.)

-- ============================================================
-- RADACCT
-- RADIUS hesaplarını (accounting) tutar.
-- Kim girdi, ne kadar süre kaldı, ne kadar veri çekti vb.
-- ============================================================

CREATE TABLE IF NOT EXISTS radacct (
    radacctid BIGSERIAL PRIMARY KEY,
    acctsessionid VARCHAR(64) NOT NULL,
    acctuniqueid VARCHAR(32) NOT NULL UNIQUE,
    username VARCHAR(64) NOT NULL,
    nasipaddress VARCHAR(15) NOT NULL,
    nasportid VARCHAR(32),
    nasporttype VARCHAR(32),
    acctstarttime TIMESTAMP,
    acctupdatetime TIMESTAMP,
    acctstoptime TIMESTAMP,
    acctinterval INTEGER,
    acctsessiontime INTEGER,
    acctauthentic VARCHAR(32),
    connectinfo_start VARCHAR(50),
    connectinfo_stop VARCHAR(50),
    acctinputoctets BIGINT DEFAULT 0,
    acctoutputoctets BIGINT DEFAULT 0,
    calledstationid VARCHAR(50),
    callingstationid VARCHAR(50),
    acctterminatecause VARCHAR(32),
    servicetype VARCHAR(32),
    framedprotocol VARCHAR(32),
    framedipaddress VARCHAR(15),
    framedipv6address VARCHAR(45),
    framedipv6prefix VARCHAR(45),
    framedinterfaceid VARCHAR(44),
    delegatedipv6prefix VARCHAR(45),
    acctstartdelay INTEGER,
    acctstopdelay INTEGER
);
CREATE INDEX IF NOT EXISTS idx_radacct_username ON radacct(username);
CREATE INDEX IF NOT EXISTS idx_radacct_session ON radacct(acctsessionid);
CREATE INDEX IF NOT EXISTS idx_radacct_start ON radacct(acctstarttime);

CREATE TABLE IF NOT EXISTS mac_devices (
    id SERIAL PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL UNIQUE,
    device_name VARCHAR(128),
    device_type VARCHAR(64),
    groupname VARCHAR(64) NOT NULL DEFAULT 'guest',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mac_devices_mac ON mac_devices(mac_address);

CREATE TABLE IF NOT EXISTS nas (
    id SERIAL PRIMARY KEY,
    nasname VARCHAR(128) NOT NULL,
    shortname VARCHAR(32),
    type VARCHAR(30) DEFAULT 'other',
    ports INTEGER,
    secret VARCHAR(60) NOT NULL,
    server VARCHAR(64),
    community VARCHAR(50),
    description VARCHAR(200)
);
