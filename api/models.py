""" Pydantic modelleri """

from pydantic import BaseModel
from datetime import datetime 

class UserInfo(BaseModel):
    username : str 
    group: str
    vlan: str | None = None 
    is_online: bool = False

class ActiveSession(BaseModel):
    username: str 
    session_id: str 
    nas_ip: str 
    framed_ip: str | None = None 
    start_time: str 
    session_time: str 
    input_octets: int = 0
    output_octets: int = 0

class MacDevice(BaseModel):
    mac_adress: str 
    device_name: str | None = None 
    device_type: str | None = None 
    groupname: str = "guest"
    is_active: bool = True 

