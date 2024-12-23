from datetime import datetime
from typing import List, Union, Optional

from pydantic import BaseModel

class pydantic_request_login_auth(BaseModel):
    login_name: str
    password: str
    source_ip_address: str | None = None
    source_device: str | None = None
    source_browser: str | None = None
    source_os: str | None = None
    referer: str | None = None

class pydantic_internal_ldap_auth(BaseModel):
    base_distinguished_name: str
    bind_username_fetched: str
    bind_password: str
    source_ip_address: str | None = None
    server_ip_or_name: str | None = None
    replica_server_ip_or_name: str | None = None
    server_port: int
    connect_timeout: int
    server_identity_check: bool
    certificate: str | None = None