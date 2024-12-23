from pydantic import BaseModel, field_validator, model_validator, ValidationInfo, ValidationError, EmailStr
from pydantic.errors import PydanticErrorMixin
from typing import Dict, List, Union, Optional
from datetime import datetime, date, time

import ipaddress
import psutil
import pytz
import re
import json

# class
from core.classes.class_administration import class_administration
from core.classes.class_configuration import class_configuration

# Define custom error classes inheriting from PydanticErrorMixin
class CustomValueError(ValueError, PydanticErrorMixin):
    pass

class InvalidIPAddressError(CustomValueError):
    def __init__(self, ip_address: str):
        self.message = f"Invalid IP address: {ip_address}"
        super().__init__(self.message)

class InvalidNetmaskError(CustomValueError):
    def __init__(self, netmask: str):
        self.message = f"Invalid network mask: {netmask}"
        super().__init__(self.message)

class InvalidGatewayError(CustomValueError):
    def __init__(self, gateway: str, ip: str, netmask: str):
        self.message = f"Gateway {gateway} is not in the network range defined by IP {ip} and netmask {netmask}"
        super().__init__(self.message)

class SystemDeviceConfig(BaseModel):
    system_device_hostname: str
    system_device_dns_domain: str
    system_device_timezone: str

    @field_validator('system_device_hostname')
    def validate_hostname(cls, value):

        # Check if the hostname contains only letters and numbers (no symbols)
        if not re.match("^[A-Za-z0-9]+$", value):
            raise CustomValueError("Hostname can only contain alphabetic characters and numbers (no symbols).")

        if len(value) < 4 or len(value) > 20:
            raise CustomValueError("Hostname must be between 4 and 20 characters long.")
        
        return value

    @field_validator('system_device_dns_domain')
    def validate_dns_domain(cls, value):
        if not (1 <= len(value) <= 30 and '.' in value):
            raise CustomValueError("DNS domain must be a valid domain name.")
        return value

    @field_validator('system_device_timezone')
    def validate_timezone(cls, value):
        if value not in pytz.all_timezones:
            raise CustomValueError(f"Invalid timezone: {value}.")
        return value

class SystemManagementConfig(BaseModel):
    system_management_ip: str
    system_management_netmask: str
    system_management_gateway: str

    @field_validator('system_management_ip')
    def validate_ip(cls, value):
        try:
            ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            raise InvalidIPAddressError(value)
        return value

    @field_validator('system_management_netmask')
    def validate_netmask(cls, value):
        try:
            ipaddress.IPv4Network(f"0.0.0.0/{value}", strict=False)  # Create a network with no host bits set
        except (ValueError, ipaddress.NetmaskValueError):
            raise InvalidNetmaskError(value)
        return value

    @model_validator(mode='before')
    def validate_gateway(cls, values):
        ip = values.get('system_management_ip')
        netmask = values.get('system_management_netmask')
        gateway = values.get('system_management_gateway')

        if ip is None or netmask is None:
            raise ValueError("IP and netmask are required to validate the gateway")
        
        try:
            ip_addr = ipaddress.IPv4Address(ip)
            gateway_addr = ipaddress.IPv4Address(gateway)
            netmask_network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            raise ValueError("Invalid IP address, netmask, or gateway format")
        
        if gateway_addr not in netmask_network:
            raise InvalidGatewayError(gateway, ip, netmask)

        return values
    
class SystemDnsEntity(BaseModel):
    system_dnsentity_primary_server: str
    system_dnsentity_secondary_server: str

    @staticmethod
    def validate_dns_address(value: str) -> str:
        # Attempt to parse the value as an IP address
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            # If it's not an IP address, validate it as an FQDN
            if not isinstance(value, str) or not value:
                raise ValueError("Invalid DNS server IP address or FQDN")
            if '..' in value or value.startswith('-') or value.endswith('-'):
                raise ValueError("Invalid DNS server FQDN")
            
            # Ensure the FQDN includes at least two dots
            if value.count('.') < 2:
                raise ValueError("Invalid FQDN address")

            # Regular expression for validating FQDN
            fqdn_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
            if not re.match(fqdn_regex, value):
                raise ValueError("Invalid DNS server FQDN")
            
            return value

    @field_validator('system_dnsentity_primary_server')
    def validate_primary_server(cls, value):
        return cls.validate_dns_address(value)

    @field_validator('system_dnsentity_secondary_server')
    def validate_secondary_server(cls, value):
        return cls.validate_dns_address(value)
    
class SystemNtpEntity(BaseModel):
    system_ntpentity_servers: List[str] = []

    @classmethod
    def transform_data(cls, data: dict):
        try:
            # Extract and validate the servers that start with 'system_ntpentity_server_'
            servers = [
                cls.validate_ntp_address(value) for key, value in data.items()
                if key.startswith('system_ntpentity_server_')
            ]
            
            # Remove invalid entries (those that returned None)
            valid_servers = [server for server in servers if server is not None]

            # Remove duplicates by converting the list to a set, then back to a list
            unique_servers = list(set(valid_servers))

            # If the list of valid and unique servers is empty, raise a ValueError
            if not unique_servers:
                raise ValueError("No valid NTP servers found.")

            # Create and return an instance of the Pydantic model with validated data
            return cls(system_ntpentity_servers=unique_servers)

        except ValueError as ve:
            # Catch the ValueError and return a standard ValueError
            raise ValueError(f"Validation failed for NTP server: {ve}")

    @staticmethod
    def validate_ntp_address(value: str, allow_empty: bool = False) -> str:
        if allow_empty and not value:  # Allow empty strings for optional servers
            return value
        
        # Validate as IP address
        try:
            ipaddress.ip_address(value)  # Check if it's a valid IP
            return value
        except ValueError:
            # If it's not a valid IP, validate as an FQDN
            fqdn_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
            if not re.match(fqdn_regex, value) or value.count('.') < 2:
                return None  # Invalid FQDN, return None to filter it out
            return value
    

class InternalNetworkConfig(BaseModel):
    internal_networks: str
    internal_networks_ignored: str = None

    @field_validator('internal_networks', mode='before')
    def split_and_validate_networks(cls, value):
        return cls.validate_ip_list(value)

    @field_validator('internal_networks_ignored', mode='before')
    def split_and_validate_ignored(cls, value):
        if value:  # Validate only if the value is present
            return cls.validate_ip_list(value)
        return value

    @staticmethod
    def validate_ip_list(value):
        ip_list = value.split(',')
        validated_ips = []

        for ip in ip_list:
            try:
                if '/' not in ip:
                    ip_network = ipaddress.ip_network(f'{ip}/32', strict=False)
                else:
                    ip_network = ipaddress.ip_network(ip, strict=False)

                validated_ips.append(str(ip_network))
            except ValueError:
                # Skip invalid IPs without raising an error
                continue

        if not validated_ips:
            raise ValueError('No valid IP addresses or networks were found.')

        return ','.join(validated_ips)
    
class SegmentHostConfig(BaseModel):
    public_id: Optional[str] = None
    segment_name: str
    segment_hosts: str

    @field_validator('public_id', mode='before')
    def check_public_id(cls, value):
        if value is not None and not value.isdigit():
            raise ValueError('public_id must contain only numeric characters.')
        return value
    
    @field_validator('segment_name')
    def validate_segment_name(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('Name cannot contain XSS tags')
        
        return value

    @field_validator('segment_hosts', mode='before')
    def validate_segment_hosts(cls, value):
        if value:
            return cls.validate_ip_list(value)
        return value

    @staticmethod
    def validate_ip_list(value):
        ip_list = value.split(',')
        validated_ips = set()  # Use a set to ensure uniqueness
        invalid_ips = []

        for ip in ip_list:
            try:
                if ip != "0.0.0.0/0" and ip != "0.0.0.0/0.0.0.0" and not ip.startswith("0.0.0.0") and not ip.endswith("/0"):
                    if '/' not in ip:
                        ip_network = ipaddress.ip_network(f'{ip}/32', strict=False)
                    else:
                        ip_network = ipaddress.ip_network(ip, strict=False)

                    validated_ips.add(ip_network)  # Add to set for uniqueness
            except ValueError:
                # Log the invalid IP for debugging
                invalid_ips.append(ip)
                continue

        if not validated_ips:
            raise ValueError('No valid networks were found.')

        # Remove networks that are covered by others
        unique_networks = []
        for network in validated_ips:
            if not any(network != other and network.subnet_of(other) for other in validated_ips):
                unique_networks.append(str(network))  # Convert to string before adding to the list

        return ','.join(unique_networks)  # Return unique validated networks as a comma-separated string

class SegmentGroupHost(BaseModel):
    segment_host_groups: List[Dict[str, str]] = []  # List to store dicts with host group info

    @classmethod
    def transform_data(cls, data):
        transformed_data = {}

        # Regular expression to match valid names (alphanumeric, spaces, ., -, _ allowed, no special characters like ?)
        valid_name_regex = re.compile(r'^[a-zA-Z0-9 ._-]+$')

        # Iterate through data keys and values
        for key, value in data.items():
            if key.startswith('segment_group_name_'):
                group_number = key.split('_')[-1]
                hosts_key = f'segment_group_hosts_{group_number}'
                
                # Validate the group name (value)
                if not valid_name_regex.match(value):
                    # Skip this group if the name is invalid (e.g., contains ?)
                    continue
                
                if hosts_key in data:
                    hosts_value = data[hosts_key]
                    valid_ips = []

                    # Process the IPs in the hosts_value
                    for ip in [x.strip() for x in hosts_value.split(',')]:
                        try:
                            if ip != "0.0.0.0/0" and ip != "0.0.0.0/0.0.0.0" and not ip.startswith("0.0.0.0") and not ip.endswith("/0"):
                                ip_obj = ipaddress.ip_network(ip, strict=False)
                                valid_ips.append(str(ip_obj))
                        except ValueError:
                            pass

                    # Append valid IPs to the correct group
                    if valid_ips:
                        if value not in transformed_data:
                            transformed_data[value] = valid_ips
                        else:
                            transformed_data[value].extend(valid_ips)

        # Remove duplicates and merge IPs for each group
        final_data = []
        for name, ips in transformed_data.items():
            # Remove duplicate IPs and join them into a comma-separated string
            unique_ips = list(set(ips))
            final_data.append({
                'name': name,
                'value': ', '.join(unique_ips)
            })

        # Return an instance of the class with the transformed data
        return cls(
            segment_host_groups=final_data
        )

class IncidentTriage(BaseModel):
    incident_triage_auto: str = "off"  # Default to "off" as a string

    @field_validator('incident_triage_auto', mode='before')
    def validate_incident_triage_auto(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
class IncidentStorage(BaseModel):
    incident_storage_local: str = "off"  # Default to "off" as a string
    incident_storage_retention_period: int
    incident_storage_data_max_size: int
    incident_storage_portionOfevents_flushed: int

    @field_validator('incident_storage_local', mode='before')
    def validate_incident_storage_local(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('incident_storage_retention_period')
    def validate_incident_storage_retention_period(cls, v):
        if v < 2 or v > 90:
            raise ValueError('Invalid Retention Period. Must be between 2 days and 90 days.')
        return v
    
    @field_validator('incident_storage_data_max_size')
    def validate_incident_storage_data_max_size(cls, v):
        if v < 100 or v > 10000:
            raise ValueError('Invalid Data Max Size. Must be between 100MB and 10000MB.')
        return v

    @field_validator('incident_storage_portionOfevents_flushed')
    def validate_incident_storage_portionOfevents_flushed(cls, v):
        if v < 1 or v > 50000:
            raise ValueError('Invalid Flush Portion of Events. Must be between 1 event and 50000 events.')
        return v
    
class IncidentTuning(BaseModel):
    incident_tuning_memory_cache_size: int
    incident_tuning_bulk_size: int

    @field_validator('incident_tuning_memory_cache_size')
    def validate_incident_tuning_memory_cache_size(cls, v):
        if v < 1:
            raise ValueError('Invalid Memory Cache Size. Must be bigger than 0.')
        return v
    
    @field_validator('incident_tuning_bulk_size')
    def validate_incident_tuning_bulk_size(cls, v):
        if v < 10:
            raise ValueError('Invalid Bulk Batch Size. Must be bigger than 10.')
        return v

class SnmpAgentService(BaseModel):
    snmp_agent_service: str = "off"  # Default to "off" as a string

    @field_validator('snmp_agent_service', mode='before')
    def validate_snmp_agent_service(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
class SnmpAgentSetting(BaseModel):
    snmp_setting_username: str
    snmp_setting_query_port: int
    snmp_setting_authentication_status: str = "off"  # Default to "off" as a string
    snmp_setting_authentication_password: Optional[str] = None
    snmp_setting_authentication_algorithm: Optional[str] = None
    snmp_setting_privacy_status: str = "off"  # Default to "off" as a string
    snmp_setting_privacy_password: Optional[str] = None
    snmp_setting_privacy_encryption: Optional[str] = None

    @field_validator('snmp_setting_username')
    def validate_snmp_setting_username(cls, value):

        # Check if the username contains any symbols or numbers
        if not re.match("^[A-Za-z]+$", value):
            raise ValueError("Username can only contain alphabetic characters (no symbols or numbers).")
        
        # Check the length of the username (between 4 and 20 characters)
        if len(value) < 4 or len(value) > 20:
            raise CustomValueError("Username must be between 4 and 20 characters long.")
        
        return value 

    @field_validator('snmp_setting_query_port')
    def validate_snmp_setting_query_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError('Invalid query port. Must be between 1 and 65535.')
        return v
    
    @field_validator('snmp_setting_authentication_status', mode='before')
    def validate_snmp_setting_authentication_status(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('snmp_setting_privacy_status', mode='before')
    def validate_snmp_setting_privacy_status(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

    @model_validator(mode='before')
    def check_authentication_and_privacy(cls, values):

        algorithm = values.get('snmp_setting_authentication_algorithm')
        encryption = values.get('snmp_setting_privacy_encryption')

        if values.get('snmp_setting_authentication_status') and (not values.get('snmp_setting_authentication_password') or not algorithm):
            raise ValueError("Authentication password or algorithm can not be empty")
        
        if values.get('snmp_setting_privacy_status') and (not values.get('snmp_setting_privacy_password') or not encryption):
            raise ValueError("Privacy password or algorithm can not be empty")
        
        if algorithm and algorithm not in ["MD5","SHA","SHA-224","SHA-256","SHA-384","SHA-512"]:
            raise ValueError(f"Invalid algorithm: {algorithm}.")
    
        if encryption and encryption not in ["AES","AES-192","AES-256"]:
            raise ValueError(f"Invalid encryption: {encryption}.")
        
        return values

class SnmpAgentAccesslist(BaseModel):
    snmp_accesslist_hosts: List[str] = []

    @classmethod
    def transform_data(cls, data: dict):
        # Extract and validate the hosts that start with 'snmp_accesslist_host_'
        hosts = [
            cls.validate_and_convert_to_cidr(value) for key, value in data.items() 
            if key.startswith('snmp_accesslist_host_')
        ]
        
        # Remove invalid entries (those that returned None)
        valid_hosts = [host for host in hosts if host is not None]

        # Remove duplicates by converting the list to a set, then back to a list
        unique_hosts = list(set(valid_hosts))

        # If the list of valid and unique hosts is empty, raise a ValueError
        if not unique_hosts:
            raise ValueError("No valid IP addresses or CIDR blocks found.")

        # Return an instance of the Pydantic model with validated and unique hosts
        return cls(snmp_accesslist_hosts=unique_hosts)

    @staticmethod
    def validate_and_convert_to_cidr(value: str) -> str:
        try:
            # Parse the IP address and convert to CIDR notation
            ip_obj = ipaddress.ip_network(value, strict=False)  # This handles IPs and CIDR
            return str(ip_obj)
        except ValueError:
            # If it's not a valid IP, return None (indicating it should be removed)
            return None
        
class LogSettingLocal(BaseModel):
    log_local_status: str = "off"  # Default to "off" as a string
    log_local_retention_period: int

    @field_validator('log_local_status', mode='before')
    def validate_log_local_status(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('log_local_retention_period')
    def validate_log_local_retention_period(cls, v):
        if v < 1 or v > 30:
            raise ValueError('Invalid Retention Period. Must be between 1 day and 30 days.')
        return v
    
class LogSettingSyslog(BaseModel):
    log_syslog_status: str = "off"  # Default to "off"
    log_syslog_servers: List[Dict[str, str]] = []  # List to store dicts with server info

    # Validate 'log_syslog_status' field before it's processed
    @classmethod
    def validate_log_syslog_status(cls, v):
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

    # Validate the server dictionary for each IP, protocol, and port
    @classmethod
    def validate_server(cls, server: Dict[str, str]) -> bool:
        # Validate IP
        try:
            ipaddress.ip_address(server['ip'])
        except ValueError:
            return False  # Invalid IP

        # Validate Protocol (must be either 'TCP' or 'UDP')
        if server['protocol'] not in ['TCP', 'UDP']:
            return False  # Invalid protocol

        # Validate Port (must be between 1 and 65535)
        try:
            port = int(server['port'])
            if not (1 <= port <= 65535):
                return False  # Invalid port
        except ValueError:
            return False  # Port is not an integer

        return True  # If all checks pass

    @classmethod
    def transform_data(cls, data: Dict[str, str]):
        # Check if no servers are present in the data
        if not any(key.startswith('log_syslog_server_ip_') for key in data):
            if data.get('log_syslog_status'):
                raise ValueError("No servers found in the provided data.")
            return cls(log_syslog_status=data.get('log_syslog_status', 'off'), log_syslog_servers=[])
        
        # Prepare the servers list
        servers = []

        # Extract server info based on the pattern "log_syslog_server_ip_*"
        index = 1
        while f'log_syslog_server_ip_{index}' in data:
            server_ip = data.get(f'log_syslog_server_ip_{index}')
            protocol = data.get(f'log_syslog_server_protocol_{index}')
            port = data.get(f'log_syslog_server_port_{index}')

            # Check if any required field is missing
            if not all([server_ip, protocol, port]):
                raise ValueError(f"Missing required fields for server {index}: IP, protocol, or port.")

            # Combine server info into a dictionary
            server = {
                'ip': server_ip,
                'protocol': protocol,
                'port': port
            }

            # Validate server and add to the list if valid
            if cls.validate_server(server):
                servers.append(server)

            # Increment the index to look for the next server
            index += 1

        # If the list of valid servers is empty, raise a ValidationError
        if not servers:
            raise ValueError("No valid syslog servers found.")

        # Return an instance of the class with the transformed data
        return cls(
            log_syslog_status=data.get('log_syslog_status', 'off'),
            log_syslog_servers=servers
        )
    
class PEnginePlugin(BaseModel):
    pengine_plugin_service: str = 'off'  # Default to False
    pengine_virtual_firewall_action: str = 'off'  # Default to False
    pengine_dns_threat_pulse: str = 'off'  # Default to False
    pengine_dns_guardian: str = 'off'  # Default to False
    pengine_ot_protocol_detector: str = 'off'  # Default to False

    @field_validator('pengine_plugin_service', mode='before')
    def validate_pengine_plugin_service(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('pengine_virtual_firewall_action', mode='before')
    def validate_pengine_virtual_firewall_action(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('pengine_dns_threat_pulse', mode='before')
    def validate_pengine_dns_threat_pulse(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('pengine_dns_guardian', mode='before')
    def validate_pengine_dns_guardian(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('pengine_ot_protocol_detector', mode='before')
    def validate_pengine_ot_protocol_detector(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

class PEngineChannelConfig(BaseModel):
    pengine_channel_monitor_interface: str
    pengine_channel_monitor_vlan_option: str
    pengine_channel_response_interface: str
    pengine_channel_response_vlan_option: str

    @field_validator('pengine_channel_monitor_interface')
    def validate_monitor_interface(cls, value):
        # For example, check if the interface is in a list of allowed interfaces
        allowed_interfaces = [iface for iface in psutil.net_if_addrs().keys() 
                    if iface.startswith(("eth", "en"))]
        
        if value not in allowed_interfaces:
            raise ValueError(f"Invalid interface: {value}. Must be one of {allowed_interfaces}")
        return value

    @field_validator('pengine_channel_response_interface')
    def validate_response_interface(cls, value):
        # For example, check if the interface is in a list of allowed interfaces
        allowed_interfaces = [iface for iface in psutil.net_if_addrs().keys() 
                    if iface.startswith(("eth", "en"))]
        
        if value not in allowed_interfaces:
            raise ValueError(f"Invalid interface: {value}. Must be one of {allowed_interfaces}")
        return value

    @field_validator('pengine_channel_monitor_vlan_option')
    def validate_monitor_vlan_option(cls, value):
        allowed_vlan_options = ['all', 'tagged', 'untagged']
        if value not in allowed_vlan_options:
            raise ValueError(f"Invalid VLAN option: {value}. Must be one of {allowed_vlan_options}")
        return value

    @field_validator('pengine_channel_response_vlan_option')
    def validate_response_vlan_option(cls, value):
        allowed_vlan_options = ['matched', 'untagged']
        if value not in allowed_vlan_options:
            raise ValueError(f"Invalid VLAN option: {value}. Must be one of {allowed_vlan_options}")
        return value

    @model_validator(mode='before')
    def check_interfaces_are_different(cls, values):
        if values.get('pengine_channel_monitor_interface') == values.get('pengine_channel_response_interface'):
            raise ValueError("Monitor and Response interface cannot be the same")
        return values

class RInspectPlugin(BaseModel):
    rinspection_plugin_service: str = 'off'  # Default to False
    rinspection_plugin_port_scanner: str = 'off'  # Default to False
    rinspection_plugin_admission_newip: str = 'off'  # Default to False
    rinspection_plugin_admission_dhcprequest: str = 'off'  # Default to False
    rinspection_plugin_recheck_interval: int
    rinspection_plugin_purge_timeout: int

    @field_validator('rinspection_plugin_service', mode='before')
    def validate_rinspection_plugin_service(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('rinspection_plugin_port_scanner', mode='before')
    def validate_rinspection_plugin_port_scanner(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

    @field_validator('rinspection_plugin_admission_newip', mode='before')
    def validate_rinspection_plugin_admission_newip(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

    @field_validator('rinspection_plugin_admission_dhcprequest', mode='before')
    def validate_rinspection_plugin_admission_dhcprequest(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('rinspection_plugin_recheck_interval', mode='before')
    def validate_rinspection_plugin_recheck_interval(cls, v):
        if int(v) < 1:
            raise ValueError('Invalid Recheck interval. Must be bigger than 0.')
        return int(v)

    @field_validator('rinspection_plugin_purge_timeout', mode='before')
    def validate_rinspection_plugin_purge_timeout(cls, v):
        if int(v) < 7:
            raise ValueError('Invalid Inactivity Timeout. Must be bigger than 7 days.')
        return int(v)
    
class RInspectScope(BaseModel):
    rinspection_scope_segments: List[str] = []
    rinspection_scope_network_ports: str = ''

    @field_validator('rinspection_scope_network_ports')
    def validate_rinspection_scope_network_ports(cls, v):
        ports = set(int(port) for port in v.split(','))
        if not ports:
            raise ValueError("At least one port number is required")
        if not all(1 <= port <= 65535 for port in ports):
            raise ValueError("Port numbers must be between 1 and 65535")
        return ','.join(map(str, sorted(ports)))

class EmailServerConfig(BaseModel):
    email_server_status: str = 'off'
    email_server_host: str
    email_server_security_mode: str
    email_server_port: int
    email_server_username: EmailStr
    email_server_authentication: str = 'off'
    email_server_password: str
    email_server_replyto: EmailStr

    @field_validator('email_server_status', mode='before')
    def validate_email_server_status(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('email_server_host')
    def validate_email_server_host(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            if '.' in v:  # assume it's a FQDN
                parts = v.split('.')
                if len(parts) > 1 and all(part for part in parts): #FQDN validation
                    return v
                else:
                    raise ValueError('Invalid SMTP Server')
            else:
                raise ValueError('Invalid SMTP Server')
    
    @field_validator('email_server_security_mode')
    def validate_email_server_security_mode(cls, v):
        allowed_modes = ['none', 'smtps', 'starttls']
        if v not in allowed_modes:
            raise ValueError('Invalid security mode')
        return v

    @field_validator('email_server_port')
    def validate_email_server_port(cls, v):
        if not 0 < v < 65535:
            raise ValueError('Invalid port number')
        return v

    @field_validator('email_server_authentication', mode='before')
    def validate_email_server_authentication(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @model_validator(mode='before')
    def check_authentication_state(cls, values):
        if values.get('email_server_authentication') == 'on':
            if not values.get('email_server_password'):
                raise ValueError('Password cannot be blank since authentication enabled')
            if re.search(r'<|>|\/|script|javascript|alert|onerror', values.get('email_server_password'), re.IGNORECASE):
                raise ValueError('Password cannot contain XSS tags')
        
        if 'email_server_authentication' not in values:
            # Flush the email_server_password
            values['email_server_password'] = ''

        return values
    

class EmailAlertConfig(BaseModel):
    email_alert_status: str = 'off'
    email_alert_interval: int
    email_alert_recipient: EmailStr

    @field_validator('email_alert_status', mode='before')
    def validate_email_alert_status(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

    @field_validator('email_alert_interval')
    def validate_email_alert_interval(cls, v):
        if not 0 < v < 10080:
            raise ValueError('Invalid interval')
        return v
    

class UserManagementUserConfig(BaseModel):
    public_id: Optional[str] = None
    login_name: str
    display_name: str
    user_type: str
    directory_source: Optional[str] = None
    new_password: Optional[str] = None
    backup_password: Optional[str] = None
    confirm_password: Optional[str] = None
    role: Optional[str] = None
    team: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    description: Optional[str] = None
    authentication_profile: str
    cannot_change_password: bool = False
    change_password_at_next_login: bool = False
    password_never_expires: bool = False
    suspend_lock: bool = False
    suspend_lock_until_date: Optional[date] = None
    automated_account_expiry: bool = False
    automated_account_expiry_date: Optional[date] = None
    time_based_access_control: bool = False
    time_based_access_control_timezone: Optional[str] = 'Turkey'
    time_based_access_control_start: time
    time_based_access_control_end: time
    time_based_access_control_days: List[str] = []
    trusted_host_access_control: bool = False
    trusted_hosts: str
    enabled: bool = True

    @classmethod
    def get_full_configuration(cls):
        """Retrieve the full configuration once per call."""
        return class_configuration().return_configuration_full()
    
    @model_validator(mode='before')
    def check_requirements(cls, values):
        # Determine if creating a new user or editing an existing one
        is_create_mode = values.get('public_id') is None
        user_type = values.get('user_type')

        # Validation for create mode
        if is_create_mode:
            if user_type == 'local':
                cls.validate_passwords(values, 'new_password', 'confirm_password')
            elif user_type == 'remoterevert':
                cls.validate_passwords(values, 'backup_password', 'confirm_password')
        
        # Validation for edit mode
        else:
            if user_type == 'local' and values.get('new_password'):
                cls.validate_passwords(values, 'new_password', 'confirm_password')
            elif user_type == 'remoterevert' and values.get('backup_password'):
                cls.validate_passwords(values, 'backup_password', 'confirm_password')

        if user_type == "local":
            values['directory_source'] = ''
        
        return values

    @staticmethod
    def validate_passwords(values, password_field, confirm_field):
        """Helper method to validate password and confirm password match."""
        password = values.get(password_field)
        confirm_password = values.get(confirm_field)

        if not password or not confirm_password:
            raise ValueError(f'Both {password_field} and {confirm_field} are required.')
        if password != confirm_password:
            raise ValueError(f'{password_field.capitalize()} and {confirm_field} do not match.')

    @field_validator('public_id', mode='before')
    def check_public_id(cls, value):
        if value is not None and not value.isdigit():
            raise ValueError('public_id must contain only numeric characters.')
        return value
    
    @field_validator('login_name')
    def validate_login_name(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('login_name cannot contain XSS tags')
        
        return value

    @field_validator('display_name')
    def validate_display_name(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('display_name cannot contain XSS tags')
        
        return value

    @field_validator('description')
    def validate_descriptione(cls, value):
        if value is None or value == '':
            return value
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('description cannot contain XSS tags')
        
        return value

    @field_validator('user_type')
    def validate_user_type(cls, value):
        # Get user types
        user_types = cls.get_full_configuration()['usermanagement_user_types']

        # Create a list of allowed type using list comprehension
        allowed_types = [type['value'] for type in user_types]
        
        # Validate the type
        if value not in allowed_types:
            raise ValueError('Invalid user type')
        
        return value

    @field_validator('directory_source')
    def validate_directory_source(cls, value):
        if value is None or value == '':
            return value
        if not class_administration().return_administration_usermanagement_directory_by_public_id(value):
            raise ValueError('Invalid Directory Connector')
        
        return value

    @field_validator('role')
    def validate_role(cls, value):
        if value is None or value == '':  # Allow None (optional field)
            return 'readonly'
        
        # Get user roles
        user_roles = cls.get_full_configuration()['usermanagement_user_roles']
        
        # Create a list of allowed roles using list comprehension
        allowed_roles = [type['value'] for type in user_roles]
        
        # Validate the role
        if value not in allowed_roles:
            raise ValueError('Invalid user role')
        
        return value

    @field_validator('team')
    def validate_team(cls, value):
        if not value:
            raise ValueError('Team is required')
        if not class_administration().return_team_by_public_id(value):
            raise ValueError('Invalid team')
        return value
    
    @field_validator('authentication_profile')
    def validate_authentication_profile(cls, value):
        if not class_administration().return_administration_authentication_profile_by_public_id(value):
            raise ValueError('Invalid authentication profile')
        return value

    @field_validator('email', mode='before')
    def validate_email(cls, value):
        """Custom validator for email."""
        if value is None or value == '':  # Allow None or empty string
            return None
        
        # Email validation is handled by EmailStr, but you can add custom logic if needed
        return value

    @field_validator('phone')
    def validate_phone(cls, value):
        """Custom validator for phone number format."""
        if value is None or value == '':  # Allow None (optional field)
            return None

        # removes a specific characters - space, plus, ()
        new_value = re.sub(r'[ +()]+', '', value)
        
        # Regular expression for validating phone number
        phone_regex = r'^(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}$'
        
        if not re.match(phone_regex, new_value):
            raise ValueError('Invalid phone number format. Please use a valid format.')
        
        return new_value
    
    @field_validator('trusted_host_access_control', mode='before')
    def validate_trusted_host_access_control(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False


    @field_validator('trusted_hosts', mode='before')
    def validate_trusted_hosts(cls, value):
        if value:
            return cls.validate_ip_list(value)
        return value

    @staticmethod
    def validate_ip_list(value):
        ip_list = value.split(',')
        validated_ips = set()  # Use a set to ensure uniqueness
        invalid_ips = []

        for ip in ip_list:
            try:
                if ip != "0.0.0.0/0" and ip != "0.0.0.0/0.0.0.0" and not ip.startswith("0.0.0.0") and not ip.endswith("/0"):
                    if '/' not in ip:
                        ip_network = ipaddress.ip_network(f'{ip}/32', strict=False)
                    else:
                        ip_network = ipaddress.ip_network(ip, strict=False)

                    validated_ips.add(ip_network)  # Add to set for uniqueness
            except ValueError:
                # Log the invalid IP for debugging
                invalid_ips.append(ip)
                continue

        if not validated_ips:
            raise ValueError('No valid networks were found.')

        # Remove networks that are covered by others
        unique_networks = []
        for network in validated_ips:
            if not any(network != other and network.subnet_of(other) for other in validated_ips):
                unique_networks.append(str(network))  # Convert to string before adding to the list

        return ','.join(unique_networks)  # Return unique validated networks as a comma-separated string
    

    @field_validator('cannot_change_password', mode='before')
    def validate_cannot_change_password(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('change_password_at_next_login', mode='before')
    def validate_change_password_at_next_login(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('password_never_expires', mode='before')
    def validate_password_never_expires(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('suspend_lock', mode='before')
    def validate_suspend_lock(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('automated_account_expiry', mode='before')
    def validate_automated_account_expiry(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('suspend_lock_until_date', 'automated_account_expiry_date', mode='before')
    def validate_dates(cls, value):
        # Treat the string 'None' as None
        if isinstance(value, str) and value.strip().lower() == "none":
            return None  # Treat 'None' string as None
        
        if isinstance(value, str) and value.strip() == "":
            return None  # Ignore empty string and treat as None

        if value is not None:
            if isinstance(value, date):
                return value  # Valid date
            elif isinstance(value, str):
                try:
                    return date.fromisoformat(value)  # Parse 'YYYY-MM-DD'
                except ValueError:
                    raise ValueError('Must be a valid date string in YYYY-MM-DD format')
            else:
                raise ValueError('Must be a valid date object or string')
        return None  # If value is None, also return None
    
    @field_validator('time_based_access_control', mode='before')
    def validate_time_based_access_control(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False


    @field_validator('time_based_access_control_timezone')
    def validate_time_based_access_control_timezone(cls, value):
        if value not in pytz.all_timezones:
            raise CustomValueError(f"Invalid timezone: {value}.")
        return value

    @field_validator('time_based_access_control_start', mode='before')
    def set_default_start_time(cls, value):
        if isinstance(value, str):
            try:
                # Parse the string to a time object
                value = datetime.strptime(value, "%H:%M").time()
            except ValueError:
                raise ValueError('Must be a valid time in HH:MM format')

        if value is not None and not isinstance(value, time):
            raise ValueError('Must be a valid time')
        
        return value or time(9, 0)  # Set to 09:00 if None
    
    @field_validator('time_based_access_control_end', mode='before')
    def set_default_end_time(cls, value):
        if isinstance(value, str):
            try:
                # Parse the string to a time object
                value = datetime.strptime(value, "%H:%M").time()
            except ValueError:
                raise ValueError('Must be a valid time in HH:MM format')

        if value is not None and not isinstance(value, time):
            raise ValueError('Must be a valid time')
        
        return value or time(17, 0)  # Set to 17:00 if None
    
    @field_validator('time_based_access_control_days')
    def validate_time_based_access_control_days(cls, value):
        valid_days = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
        if not all(day in valid_days for day in value):
            raise ValueError(f'Invalid day(s) of week found.')
        return value
    
    @field_validator('enabled', mode='before')
    def validate_enabled(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False


class UserManagementTeamConfig(BaseModel):
    public_id: Optional[str] = None
    name: str
    description: Optional[str] = None

    @field_validator('public_id', mode='before')
    def check_public_id(cls, value):
        if value is not None and not value.isdigit():
            raise ValueError('public_id must contain only numeric characters.')
        return value

    @field_validator('name')
    def validate_team_name(cls, value):
        # Check if the name contains only letters, numbers, spaces and some allowed symbols
        if not re.match("^[A-Za-z0-9 ._-]+$", value):
            raise CustomValueError("Team name can contains only letters, numbers, spaces and some allowed symbols (._-)")

        if len(value) < 4 or len(value) > 30:
            raise CustomValueError("Team name must be between 4 and 30 characters long.")
        
        return value
    
    @field_validator('description')
    def validate_description(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('Description cannot contain XSS tags')
        
        return value
    
class LdapServerDirectoryConfig(BaseModel):
    public_id: Optional[str] = None
    name: str
    enabled: bool = False
    readonly: bool = False
    autocreate: bool = False
    base_distinguished_name: str
    netbios_hostname: str
    server_ip_or_name: str
    replica_server_ip_or_name: Optional[str] = None
    secure_connection: bool = False
    server_port: int
    common_name_identifier: str
    connect_timeout: int
    description: Optional[str] = None
    bind_username: str
    bind_password: Optional[str] = None
    server_identity_check: bool = False  # Default to False
    certificate: Optional[str] = None

    @field_validator('public_id', mode='before')
    def check_public_id(cls, value):
        if value is not None and not value.isdigit():
            raise ValueError('public_id must contain only numeric characters.')
        return value

    @field_validator('name')
    def validate_name(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('name cannot contain XSS tags')
        
        # Check if the name contains only letters, numbers, spaces and some allowed symbols
        if not re.match("^[A-Za-z0-9 ._-]+$", value):
            raise CustomValueError("Name can contains only letters, numbers, spaces and some allowed symbols (._-)")

        if len(value) < 1 or len(value) > 50:
            raise CustomValueError("Name must be between 1 and 50 characters long.")
        
        return value

    @field_validator('enabled', mode='before')
    def validate_enabled(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False
        
    @field_validator('readonly', mode='before')
    def validate_readonly(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('autocreate', mode='before')
    def validate_autocreate(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('base_distinguished_name')
    def validate_dn_format(cls, value):
        # Simple validation to check for correct DN format
        components = value.split(',')
        for component in components:
            if '=' not in component:
                raise ValueError(f"Invalid component in DN: '{component}'. Each component must contain an '='.")
            key, val = component.split('=', 1)
            if not key or not val:
                raise ValueError(f"Invalid DN component: '{component}'. Both key and value must be present.")
        return value

    @field_validator('server_ip_or_name', 'replica_server_ip_or_name')
    def validate_ip_or_fqdn(cls, v):
        if v == '':  # allow empty string for replica_server_ip_or_name
            return v
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            if '.' in v:  # assume it's a FQDN
                parts = v.split('.')
                if len(parts) > 1 and all(part for part in parts): #FQDN validation
                    return v
                else:
                    raise ValueError('Invalid FQDN address')
            else:
                raise ValueError('Invalid IP address or FQDN')

    @field_validator('secure_connection', mode='before')
    def validate_secure_connection(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('server_port')
    def validate_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError('Invalid port number. Must be between 1 and 65535.')
        return v

    @field_validator('connect_timeout')
    def validate_connect_timeout(cls, v):
        if v <= 0:
            raise ValueError('Invalid connect timeout. Must be greater than 0.')
        return v
    
    @field_validator('server_identity_check', mode='before')
    def validate_server_identity_check(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('bind_username')
    def validate_bind_username(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('bind_username cannot contain XSS tags')
        
        # Check if the name contains only letters, numbers, spaces and some allowed symbols
        if not re.match("^[A-Za-z0-9 ._-]+$", value):
            raise CustomValueError("Bind username can contains only letters, numbers, spaces and some allowed symbols (._-)")

        if len(value) < 2 or len(value) > 30:
            raise CustomValueError("Bind username must be between 2 and 30 characters long.")
        
        return value

    @field_validator('bind_password')
    def validate_bind_password(cls, value):
        if value is None or value == '':
            return value
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('bind_password cannot contain XSS tags')
        
        return value
    
    @field_validator('description')
    def validate_descriptione(cls, value):
        if value is None or value == '':
            return value
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('description cannot contain XSS tags')
        
        return value

    @model_validator(mode='before')
    def check_certificate(cls, values):
        # Ensure certificate is present if server_identity_check is True
        if values.get('server_identity_check') and not values.get('certificate'):
            raise ValueError("Certificate cannot be empty when server identity check is enabled")
        return values

class PairBrainModel(BaseModel):
    """Model for PairBrain"""
    brain_pair_status: str = "off"
    brain_pair_address: str = "0.0.0.0"
    brain_pair_port: Optional[int] = 443
    brain_pair_token: Optional[str] = None


    @staticmethod
    def validate_brain_address(value: str) -> str:
        # Check if the value is "0.0.0.0"
        if value == "0.0.0.0":
            raise ValueError("Invalid Brain IP address: cannot be 0.0.0.0")
        
        # Attempt to parse the value as an IP address
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            # If it's not an IP address, validate it as an FQDN
            if not isinstance(value, str) or not value:
                raise ValueError("Invalid Brain IP address or FQDN")
            if '..' in value or value.startswith('-') or value.endswith('-'):
                raise ValueError("Invalid Brain FQDN")
            
            # Ensure the FQDN includes at least two dots
            if value.count('.') < 2:
                raise ValueError("Invalid Brain FQDN address")

            # Regular expression for validating FQDN
            fqdn_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
            if not re.match(fqdn_regex, value):
                raise ValueError("Invalid Brain FQDN")
            
            return value

    @field_validator('brain_pair_status', mode='before')
    def validate_brain_pair_status(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

    @field_validator('brain_pair_address')
    def validate_brain_pair_address(cls, value):
        return cls.validate_brain_address(value)
    
    @field_validator('brain_pair_port')
    def validate_brain_pair_port(cls, value):
        if value < 1 or value > 65535:
            raise ValueError('Invalid port. Must be between 1 and 65535.')
        return value
    
    @field_validator('brain_pair_token')
    def validate_brain_pair_token(cls, value):
        if value is None or value == '':
            return value
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('Token cannot contain XSS tags')
        
        return value
    
    @model_validator(mode='before')
    def check_token_when_status_enabled(cls, values):
        status = values.get('brain_pair_status')
        token = values.get('brain_pair_token')

        # Strip whitespace from the token
        if token is not None:
            token = token.strip()

        if status == "on" and not token:
            raise ValueError("Token must be supplied")
        
        # Update the token in values if it was stripped
        values['brain_pair_token'] = token

        return values
    
class PolicyUserModel(BaseModel):
    """Model for PolicyUser"""
    policy_user_auto_create: str = "off"
    policy_user_suspend_inactive: str = "off"
    policy_user_idle_threshold: Optional[int] = 30

    @field_validator('policy_user_auto_create', mode='before')
    def validate_policy_user_auto_create(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_user_suspend_inactive', mode='before')
    def validate_policy_user_suspend_inactive(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_user_idle_threshold')
    def validate_policy_user_idle_threshold(cls, value):
        if value < 1 or value > 365:
            raise ValueError('Invalid day. Must be between 1 and 365.')
        return value
    
class PolicyLogonModel(BaseModel):
    """Model for PolicyLogon"""
    policy_logon_case_insensitive: str = "off"
    policy_logon_session_timeout: Optional[int] = 30
    policy_logon_lockout_threshold: Optional[int] = 5
    policy_logon_source_lockdown: str = "off"
    policy_logon_source_lockdown_duration: Optional[int] = 15
    policy_logon_map_domain_to_directory: str = "off"
    policy_logon_disclaimer_message: str = "off"
    policy_logon_disclaimer_stage: Optional[str] = 'before'
    policy_logon_disclaimer_content: Optional[str] = None

    @field_validator('policy_logon_case_insensitive', mode='before')
    def validate_policy_logon_case_insensitive(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_logon_source_lockdown', mode='before')
    def validate_policy_logon_source_lockdown(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_logon_map_domain_to_directory', mode='before')
    def validate_policy_logon_map_domain_to_directory(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_logon_disclaimer_message', mode='before')
    def validate_policy_logon_disclaimer_message(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

    @field_validator('policy_logon_source_lockdown', mode='before')
    def validate_policy_logon_source_lockdowne(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    

    @field_validator('policy_logon_session_timeout')
    def validate_policy_logon_session_timeout(cls, value):
        if value < 1 or value > 2880:
            raise ValueError('Invalid timeout. Must be between 1 and 2880 (2days).')
        return value

    @field_validator('policy_logon_lockout_threshold')
    def validate_policy_logon_lockout_threshold(cls, value):
        if value < 1 or value > 10:
            raise ValueError('Invalid threshold. Must be between 1 and 10.')
        return value

    @field_validator('policy_logon_source_lockdown_duration')
    def validate_policy_policy_logon_source_lockdown_duration(cls, value):
        if value < 1 or value > 2880:
            raise ValueError('Invalid duration. Must be between 1 and 2880 (2days).')
        return value
    
    @field_validator('policy_logon_disclaimer_stage', mode='before')
    def validate_stage(cls, value):
        if not value:
            return 'before'  # Set default value if empty
        if value not in {'before', 'after'}:
            raise ValueError("Value must be 'before' or 'after'")
        return value
    
    @model_validator(mode='before')
    def set_default_disclaimer_content(cls, values):
        # Check if disclaimer message is "on" and content is empty
        if values.get('policy_logon_disclaimer_message') == "on" and not values.get('policy_logon_disclaimer_content'):
            values['policy_logon_disclaimer_content'] = '<p>The SIBERAT AI solution provides advanced detection and response capabilities, but cannot guarantee the prevention of all cyber threats. Information is processed in accordance with applicable privacy laws and our Privacy Policy.</p><p>No liability is accepted for damages resulting from its use. Users are responsible for legal compliance and are advised to take additional security measures.</p>'
        return values
    

class PolicyPasswordModel(BaseModel):
    """Model for PolicyPassword"""
    policy_password_display_generator: str = "off"
    policy_password_show_guidelines: str = "off"
    policy_password_weak_detection: str = "off"
    policy_password_minimum_lenght: Optional[int] = 8
    policy_password_maximum_lenght: Optional[int] = 64
    policy_password_minimum_age: Optional[int] = 0
    policy_password_maximum_age: Optional[int] = 0
    policy_password_require_digit: str = "off"
    policy_password_require_letter: str = "off"
    policy_password_require_symbol: str = "off"
    policy_password_allow_username_in_password: str = "off"
    password_policy_skip_remote_users: str = "off"
    policy_password_reset_max_attempts: Optional[int] = 0

    @field_validator('policy_password_minimum_lenght')
    def validate_policy_password_minimum_lenght(cls, value):
        if value < 1 or value > 64:
            raise ValueError('Invalid lenght. Must be between 1 and 64.')
        return value

    @field_validator('policy_password_maximum_lenght')
    def validate_policy_password_maximum_lenght(cls, value):
        if value < 1 or value > 64:
            raise ValueError('Invalid lenght. Must be between 1 and 64.')
        return value

    @field_validator('policy_password_minimum_age')
    def validate_policy_password_minumum_age(cls, value):
        if value < 0 or value > 366:
            raise ValueError('Invalid age. Must be between 1 and 365.')
        return value

    @field_validator('policy_password_maximum_age')
    def validate_policy_password_maximum_age(cls, value):
        if value < 0 or value > 366:
            raise ValueError('Invalid age. Must be between 1 and 365.')
        return value

    @model_validator(mode='before')
    def check_policy_consistency(cls, values):
        # Check that minimum length is not greater than maximum length
        min_length = values.get('policy_password_minimum_length')
        max_length = values.get('policy_password_maximum_length')
        if min_length is not None and max_length is not None and min_length > max_length:
            raise ValueError("Minimum length cannot be greater than maximum length.")

        # Check that minimum age is not greater than maximum age
        min_age = values.get('policy_password_minimum_age')
        max_age = values.get('policy_password_maximum_age')
        if min_age is not None and max_age is not None and min_age > max_age:
            raise ValueError("Minimum age cannot be greater than maximum age.")
        
        return values

    @field_validator('policy_password_reset_max_attempts')
    def validate_policy_password_reset_max_attempts(cls, value):
        if value < 0 or value > 10:
            raise ValueError('Invalid max attempts. Must be between 0 and 10.')
        return value

    @field_validator('policy_password_display_generator', mode='before')
    def validate_policy_password_display_generator(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_password_show_guidelines', mode='before')
    def validate_policy_password_show_guidelines(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_password_weak_detection', mode='before')
    def validate_policy_password_weak_detection(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"

    @field_validator('policy_password_require_digit', mode='before')
    def validate_policy_password_require_digit(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_password_require_letter', mode='before')
    def validate_policy_password_require_letter(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_password_require_symbol', mode='before')
    def validate_policy_password_require_symbol(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('policy_password_allow_username_in_password', mode='before')
    def validate_policy_password_allow_username_in_password(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
    @field_validator('password_policy_skip_remote_users', mode='before')
    def validate_password_policy_skip_remote_users(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return 'on'
        return 'off'  # Default to "off" if the value is not "on"
    
class AuthenticationProfileConfig(BaseModel):
    """Authentication Profile Configuration"""
    public_id: Optional[str] = None
    name: str
    pass_through_duration: Optional[int] = 15
    challanges: List[str] = []
    questions: List[str] = []
    description: Optional[str] = None

    @field_validator('public_id', mode='before')
    def check_public_id(cls, value):
        if value is not None and not value.isdigit():
            raise ValueError('public_id must contain only numeric characters.')
        return value
    
    @field_validator('pass_through_duration')
    def validate_pass_through_duration(cls, value):
        if value < 0 or value > 10080:
            raise ValueError('Invalid duration. Must be between 0 and 10080(a week).')
        return value
    
    @field_validator('description')
    def validate_descriptione(cls, value):
        if value is None or value == '':
            return value
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('description cannot contain XSS tags')
        
        return value

    @field_validator('challanges')
    def validate_challanges(cls, value):
        valid_challanges = {"oauth", "sms", "email", "question"}
        if not all(challange in valid_challanges for challange in value):
            raise ValueError(f'Invalid challange selected.')
        return value

    @field_validator('questions')
    def validate_questions(cls, value):
        if not value:
            # If the list is empty, return it as is
            return value

        # Loop through each public_id and validate that it's numeric
        for public_id in value:
            if not public_id.isdigit():
                # Raise a detailed error message if validation fails
                raise ValueError(f'Security question ID is not valid.')
        
        # Return the validated list if all IDs are numeric
        return value

    @field_validator('name')
    def validate_name(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('name cannot contain XSS tags')
        
        # Check if the name contains only letters, numbers, spaces and some allowed symbols
        if not re.match("^[A-Za-z0-9 ._-]+$", value):
            raise CustomValueError("Name can contains only letters, numbers, spaces and some allowed symbols (._-)")

        if len(value) < 1 or len(value) > 80:
            raise CustomValueError("Name must be between 1 and 80 characters long.")
        
        return value
    
    @model_validator(mode='before')
    def check_challanges(cls, values):
        # Check if disclaimer message is "on" and content is empty
        if not values["questions"] and "question" in values["challanges"]:
            raise CustomValueError("You must select at least one question for the question challange.")
        return values
    

class AuthenticationSecQuestionConfig(BaseModel):
    """Authentication Security Question Configuration"""
    public_id: Optional[str] = None
    question: str
    answer: str
    case_sensitive : bool = False
    crypted: bool = False
    author: Optional[str] = None

    @field_validator('public_id', mode='before')
    def check_public_id(cls, value):
        if value is not None and not value.isdigit():
            raise ValueError('public_id must contain only numeric characters.')
        return value

    @field_validator('question')
    def validate_question(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('question cannot contain XSS tags')
        
        return value

    @field_validator('answer')
    def validate_answer(cls, value):
        if re.search(r'<|>|\/|script|javascript|alert|onerror', value, re.IGNORECASE):
            raise ValueError('answer cannot contain XSS tags')
        
        return value

    @field_validator('case_sensitive', mode='before')
    def validate_case_sensitive(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False

    @field_validator('crypted', mode='before')
    def validate_crypted(cls, v):
        # Check if the value is "on" from the checkbox input
        if isinstance(v, str) and v.lower() == 'on':
            return True
        return bool(v)  # Return the actual boolean value or False