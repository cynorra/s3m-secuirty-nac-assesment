-- Grup politikaları (VLAN)
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('admin', 'Tunnel-Type', ':=', 'VLAN'),
    ('admin', 'Tunnel-Medium-Type', ':=', 'IEEE-802'),
    ('admin', 'Tunnel-Private-Group-Id', ':=', '10'),
    ('admin', 'Filter-Id', ':=', 'admin-acl');

INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('employee', 'Tunnel-Type', ':=', 'VLAN'),
    ('employee', 'Tunnel-Medium-Type', ':=', 'IEEE-802'),
    ('employee', 'Tunnel-Private-Group-Id', ':=', '20'),
    ('employee', 'Filter-Id', ':=', 'employee-acl');

INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('guest', 'Tunnel-Type', ':=', 'VLAN'),
    ('guest', 'Tunnel-Medium-Type', ':=', 'IEEE-802'),
    ('guest', 'Tunnel-Private-Group-Id', ':=', '30'),
    ('guest', 'Filter-Id', ':=', 'guest-acl'),
    ('guest', 'Session-Timeout', ':=', '3600');

INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('iot', 'Tunnel-Type', ':=', 'VLAN'),
    ('iot', 'Tunnel-Medium-Type', ':=', 'IEEE-802'),
    ('iot', 'Tunnel-Private-Group-Id', ':=', '40'),
    ('iot', 'Filter-Id', ':=', 'iot-acl');

-- Kullanıcılar (şifreler bcrypt ile hashlenmiş)
INSERT INTO radcheck (username, attribute, op, value) VALUES
    ('admin1', 'Cleartext-Password', ':=', '$2b$12$Tq4xqs/xHydwtSV1Up74LuBkau/v2TrebR0UK5DUD4IK94UK/u.9a'),
    ('employee1', 'Cleartext-Password', ':=', '$2b$12$bCY9puIulnmjhbxmQIZN8.zitJsazR9zt9j0C18QE.Mp3nyG7V/xO'),
    ('employee2', 'Cleartext-Password', ':=', '$2b$12$IcLnK9FHwIZBOCvEW8oYZuWSS5P.MDuuRVHHDYUV2UtZ/XmIzfcTe'),
    ('guest1', 'Cleartext-Password', ':=', '$2b$12$/W7o5RFow1lHNR6DQoNTNe99laRTfd1cAlbg4u.S/gA9PX/W1mUxe');

INSERT INTO radusergroup (username, groupname, priority) VALUES
    ('admin1', 'admin', 1),
    ('employee1', 'employee', 1),
    ('employee2', 'employee', 1),
    ('guest1', 'guest', 1);

-- MAC cihazları
INSERT INTO mac_devices (mac_address, device_name, device_type, groupname) VALUES
    ('AA:BB:CC:DD:EE:01', 'Kat-1 Yazici', 'printer', 'iot'),
    ('AA:BB:CC:DD:EE:02', 'Lobby IP Telefon', 'ip_phone', 'employee'),
    ('AA:BB:CC:DD:EE:03', 'Guvenlik Kamerasi', 'camera', 'iot'),
    ('AA:BB:CC:DD:EE:04', 'Konferans Odasi AP', 'access_point', 'admin');

-- NAS
INSERT INTO nas (nasname, shortname, type, secret, description) VALUES
    ('127.0.0.1', 'localhost', 'other', 'testing123', 'Test NAS'),
    ('172.20.0.0/16', 'docker-net', 'other', 'testing123', 'Docker network');
