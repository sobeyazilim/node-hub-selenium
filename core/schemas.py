import re
import os

# app
app_version = '3.1.0'
app_title = "CYBERSENS Platform"
app_summary = "AI data intelligence solution"
app_company = "SOBE YAZILIM"
app_contact_name = "Murat BÜLBÜL"
app_contact_email = "murat.bulbul@sobeyazilim.com.tr"
app_terms_of_service = "https://sobeyazilim.com.tr/contact/"
app_developers = """Hüseyin ADAKLI, Mehmet ÖZDER, Murat BÜLBÜL, Ramazan ÖZÇOBAN, Rıdvan GÜLER, Talat ÖZÇOBAN, Yağız YAMAN"""
app_keywords = "threat hunting, threat intelligence, ai, data intelligence, cybersecurity"
app_description = """

Threat Hunting is our DNA🚀

Discover modernized threat hunting strategies to tackle the ever-evolving threat landscape

Developers :  %s

Version    :  %s

""" % (app_developers, app_version)

# app secret key
app_secret_key = "67f251ec63eb288ca5fe225aca46e43f5f0f2fdb3e2389fcbf1ba065666465fe"

# app fernet private key (cryptography)
app_fernet_private_key = 'wSbWLGojUq5Kbk3HpHOE1KJRHPMGwBu0MmWUosM8B9k='

# login timeout in minutes
app_login_timeout = 30

# jwt token options (openssl rand -hex 32)
app_jwt_token_label = "sobe-token"
app_jwt_key = 'a31a1354f5c37d06ed6d2c7c118141cc48ed3bcbffaffa407530b1846d1a9759'
app_jwt_symetric_algorithm = "HS256"
app_jwt_asymetric_algorithm = "RS256"

# JWT private and public keys
app_jwt_private_key = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbh8eJkab8mVlo
QnoDY1GfhnX2bohH8c01APeUigeGCt59d2risUOE/2p9X07tYMD07y84kp0kt04G
kHueA09lMAZ2RU5tACAImNxvVhnDbpwMfZq9l7KOGMOcTac3QJcjYQi+2gcZaYuN
iDr9IinaUagT3FbwHEUQYV763ft4RKvallnz9Sx+uuOfGVT6uG13ZvGrTE6ai6F0
ebrYwKRiZeTZvAAeIY7fKjKRzAC2JeZrUgpnE/pQYLCOgmXAkuxiYMvJZLnfFiQJ
H7dvkhzUaqbgiAzgvkfK3dUXHWLqhsFJcAz9jtbt69E6EIwhXXiDhpsUbeHQCsFB
QxZ4VDEnAgMBAAECggEAMqvRg9Bpwc5Hk8gcT6HiGjc4DSyQKkMGwaA6hT+i4u6p
Uj55HmAaHJ2z38Ja/nGhuCdpN96nhO0Ghn9c+Sj8b3e5Vh1DL+eifTmDT/OIuNJU
FJH9YJueLCxNIkvON/OhrxnboenDT7tL6dwy+XCkRm8oo4TtUDjGPDStbqxEOgr6
AFugdO2Wx/TaI+xP1d9wIfiNTVN62qfH//ZpnBmuDMW+DfkhuRclKbpPOiEShsdY
SZicqdHN9rAO+LMTbtDLcRyarIUbJvER70IeKb2aglKKi0CrTFXK/Y7yfU+ofssi
kC6l42iVbmR+AE2sfkkxm/2JIOZH7eygxDFWaFBM2QKBgQD/FdkfMeoc4ZB++IXQ
II31AWkNKFAau2ah1DtcEf2o6++Z18ILlehDPobD+mMiAKbuooy1jsBW4oAK0bC6
vRIf53mCkpNWxAINnfhT4xPFE4E18AqSZm+deFoa/8HdHzQiemWOVWXtq1ySq+Qa
cYgW/QH15uIoBqaz7pJt9mvABQKBgQDcUUtN8JCXZd2+2yqdcFKLhtGmePy1D/3X
+pLb5jNM20c3D1NmgeE4yz5VHUS+jpuz436arjaiqMmWLBKRI8FXFYxtkD6qvdxY
E2NosibpkRGRmuNZDdOtdtD25IAQQPJNp+BwX2Gbclo70TZurNfngTf69IYk1yyI
Guz/MeYwOwKBgD5Xh54BI/d1BUySzplkK22Sr6sAjDtMS7QHW46P8w+iwgc2XP1Z
4M72bBdfjXTU9fdikMMapVVWu/Zo8ylgZhqYBvFrg0j0VJAhaHyQBdfngW++P8cx
89tne5YXpbi2FJbMlR9pLaUdeV17Vx9DWgBMS3tety0TGxDkoLLxQ7pFAoGBAKad
LA/jL9XvCYU+hbnOqf4ulPoKYUIkt9nP+6QlMQKcifzPsEjDTCoBOkBwA/8AJiwi
jSo5OcRFVT4mUlxE6AANocdx4JKLRsmsz+7rW5YjSWAN/ITqefyi8GDmaRrhotyr
aoZQ+6XtEuRN0ZZdTGIdTNKSfaf6ugisJDLR77zlAoGASZBYwP7hcN2d7drNe3PA
BeYe8uWNcYuvXfjoQ/D7LAEuqq+RrjGwBbIBXEdqbKKuOpbhcOHFlJVVLQkaVkri
1V0qEuEt9vWb7hxJ/+KaXjaIYH3OMxhJFkgczc++rXy2h/HiJKHpTuhUo76Yc5Wr
4wmVqBlwjpye8WxA0CB2Igw=
-----END PRIVATE KEY-----"""

app_jwt_public_key = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA24fHiZGm/JlZaEJ6A2NR
n4Z19m6IR/HNNQD3lIoHhgrefXdq4rFDhP9qfV9O7WDA9O8vOJKdJLdOBpB7ngNP
ZTAGdkVObQAgCJjcb1YZw26cDH2avZeyjhjDnE2nN0CXI2EIvtoHGWmLjYg6/SIp
2lGoE9xW8BxFEGFe+t37eESr2pZZ8/UsfrrjnxlU+rhtd2bxq0xOmouhdHm62MCk
YmXk2bwAHiGO3yoykcwAtiXma1IKZxP6UGCwjoJlwJLsYmDLyWS53xYkCR+3b5Ic
1Gqm4IgM4L5Hyt3VFx1i6obBSXAM/Y7W7evROhCMIV14g4abFG3h0ArBQUMWeFQx
JwIDAQAB
-----END PUBLIC KEY-----"""

# Event limit to cache on memory
app_memory_cache_size = 200

# app debug mode
# Default to False if the environment variable is not set
app_debug_mode = os.getenv("APP_DEBUG_MODE", "False") == "True"  # Convert "True" string to boolean

# app logging mode file(False) or stream(True)
app_stream_mode = True

# app log path
app_log_path = "/sobe/log/node-sensor-web-platform.log"

# app scouting container
app_scouting_container_url = "https://192.0.2.22:9999/scouting/"

# websocket auth key
websocket_server_key = "fef38a9373bdb3c96694f030f53a4395f8bcd0b0c72005bdd15eb8e086345366"
# insert threshold for websocket incidents handler
websocket_database_insert_batch_size = 10

# postgresql/database
# Default table name for retention
database_retention_table_name = 'sensor_incidents'
# Incidents should be stored in a database
database_store_incidents = True
# In-memory storage for dynamic retention period
database_retention_period_days = 7  # Default value
# Default max size in megabytes (1 GB)
database_max_allowed_table_size = 1000 
# Delete records if table size exceeds max_allowed_table_size
database_portion_of_records_to_delete = 10000
database_identifier_to_delete_records = 'ioc_timestamp'
# database SQLAlchemy transaction tuning
database_pool_size = 10
database_max_overflow = 20

# db debug mode
database_debug_mode = False

# map switched type
map_default_tile_name = 'Transport Map'
map_switched_type = 'online' # online
map_websocket_channel_uri = '/socket/attackmap/threat'

# map application list
map_applications = [ "ADB", "ATG", "BSAP", "CODESYS", "CRIMSON", "DCOM", "DHCP", "DNS", "EMAIL", "FINS", "FOCAS", "FTP", "GE-SRTP", "GVCP", "GVSP", "HICP", "HTTP", "HTTPS", "ICCP", "IEC-60870-5-104", "IPSEC", "KERBEROS", "KNXNET IP", "LDAP", "L2TP", "MEDICAL", "MINECRAFT", "MONGODB", "MODBUS", "MTCONNECT", "MYSQL", "NTP", "OPENVPN", "ORACLE", "PC-WORX", "PLAYSTATION NETWORK", "POSTGRESQL", "PPTP", "RDP", "SIP", "SMB", "SNMP", "SQL", "SQL SERVER", "SSH", "STEAM", "TEAMSPEAK", "TELNET", "TFTP", "VNC", "XBOX LIVE", "not-applicable" ]

# environments
environment = os.getenv("ENVIRONMENT", "production")
postgresql_ip = os.getenv("POSTGRESQL_IP", "127.0.0.1")
postgresql_port = os.getenv("POSTGRESQL_PORT", "65432")
postgresql_db = os.getenv("POSTGRESQL_DB", "siberat")
postgresql_user = os.getenv("POSTGRESQL_USER", "root")
postgresql_password = os.getenv("POSTGRESQL_PASSWORD", "sobesobe")

database_sqlalchemy_database_uri = f"postgresql+psycopg2://{postgresql_user}:{postgresql_password}@{postgresql_ip}:{postgresql_port}/{postgresql_db}"

if environment == "development":
    app_log_path = "node-sensor-web-platform.log"