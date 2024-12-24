# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, DateTime, event, inspect, Text
from datetime import datetime

# providers
from core.providers.dbprovider import dbprovider, dbBase

# services
from core.services.serviceCrypt import service_cryptography
from core.services.serviceLogger import service_logger, service_logger_debug

class ModelConfiguration(dbBase):
    __tablename__ = 'configuration'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    attribute = Column(String, nullable=False, unique=True)
    value = Column(Text, nullable=True)
    crypted = Column(Boolean, nullable=True, default=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __repr__(self):
        try:
            if self.crypted:
                decrypted_value = self.crypt_to_text(self.value)
                return f"{{'{self.attribute}': {decrypted_value}}}"
            else:
                return f"{{'{self.attribute}': {self.value}}}"
            
        except Exception as e:
            service_logger().error(f"Error during __repr__: {e}")

    @staticmethod
    def text_to_crypt(value):
        try:
            if isinstance(value, str):  # Ensure value is a string before encrypting
                return service_cryptography().text_to_crypt(value)  # Use encryption, not hashing
            else:
                raise TypeError("The value to be encrypted must be a string.")
        except Exception as e:
            service_logger().warning(f"Error model text_to_crypt: {e}")
            return None  # Return None or handle error as needed

    @staticmethod
    def crypt_to_text(value):
        try:
            return service_cryptography().crypt_to_text(value)
        
        except Exception as e:
            service_logger().warning(f"Error model crypt_to_text: {e}")
            return None  # Return None or handle error as needed
    

    def _update(self):
        """Helper method to update the object in the database"""
        try:
            dbprovider.merge(self)
            dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _update: {e}")
            dbprovider.rollback()

    def _delete(self):
        """Helper method to delete the object from the database"""
        try:
            instance = dbprovider.query(ModelConfiguration).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    # Methods for accessing and modifying fields
    def return_object_attribute(self):
        return self.attribute
    
    def return_object_value(self):
        return service_cryptography().crypt_to_text(self.value)
    
    def remove_object(self):
        """Remove object from the database."""
        self._delete()

@event.listens_for(ModelConfiguration.__mapper__, 'before_insert')
@event.listens_for(ModelConfiguration.__mapper__, 'before_update')
def value_to_crypt(mapper, connection, target):
    if target.crypted:
        target.value = target.text_to_crypt(target.value)

@event.listens_for(ModelConfiguration, 'load')
def value_to_text(target, context):
    if target.crypted:
        target.value = target.crypt_to_text(target.value)

# Event listener for after_create
@event.listens_for(ModelConfiguration.__table__, 'after_create')  # type: ignore
def aftercreate_model_configuration(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelConfiguration triggered")

    try:

        dbprovider.add(ModelConfiguration(
            attribute='system_version',
            value='3.1.0'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_device_hostname',
            value='cybersens'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_device_dns_domain',
            value='sobeyazilim.com.tr'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_device_timezone',
            value='Turkey'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_management_ip',
            value='0.0.0.0'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_management_netmask',
            value='255.255.255.0'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_management_gateway',
            value='0.0.0.0'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_dnsentity_primary_server',
            value='8.8.8.8'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_dnsentity_secondary_server',
            value='1.1.1.1'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='system_ntpentity_servers',
            value='["0.tr.pool.ntp.org","time1.google.com"]'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='internal_networks',
            value='10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='internal_networks_ignored',
            value=''
        ))

        dbprovider.add(ModelConfiguration(
            attribute='incident_triage_auto',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='incident_storage_local',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='incident_storage_retention_period',
            value='7'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='incident_storage_data_max_size',
            value='5000'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='incident_storage_portionOfevents_flushed',
            value='10000'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='incident_tuning_memory_cache_size',
            value='250'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='incident_tuning_bulk_size',
            value='30'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='pengine_plugin_service',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='pengine_virtual_firewall_action',
            value='off'
        ))
        
        dbprovider.add(ModelConfiguration(
            attribute='pengine_dns_threat_pulse',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='pengine_dns_guardian',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='pengine_ot_protocol_detector',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='pengine_channel_monitor_vlan_option',
            value='all'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='pengine_channel_response_vlan_option',
            value='matched'
        ))

        
        dbprovider.add(ModelConfiguration(
            attribute='rinspection_plugin_service',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='rinspection_plugin_port_scanner',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='rinspection_plugin_admission_newip',
            value='on'
        ))
        
        dbprovider.add(ModelConfiguration(
            attribute='rinspection_plugin_recheck_interval',
            value='12'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='rinspection_plugin_purge_timeout',
            value='30'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='rinspection_scope_segments',
            value='[]'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='rinspection_scope_network_ports',
            value='20,21,22,25,53,67,80,110,143,161,389,443,993,995,1433,1521,1723,3306,3389,5432,5900,8080,8443'
        ))

        
        dbprovider.add(ModelConfiguration(
            attribute='snmp_agent_service',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_setting_username',
            value='xosnmp',
            crypted=True
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_setting_query_port',
            value='161'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_setting_authentication_status',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_setting_authentication_password',
            value='xos',
            crypted=True
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_setting_authentication_algorithm',
            value='SHA-256'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_setting_privacy_status',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_setting_privacy_password',
            value='xos',
            crypted=True
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_setting_privacy_encryption',
            value='AES-256'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='snmp_accesslist_hosts',
            value='["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='email_server_status',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='email_server_host',
            value='smtp.office365.com'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='email_server_security_mode',
            value='smtps'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='email_server_port',
            value='465'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='email_server_authentication',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='email_alert_status',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='email_alert_interval',
            value='5'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='log_local_status',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='log_local_retention_period',
            value='7'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='usermanagement_user_types',
            value='[{"value": "local", "label": "Local User"}, {"value": "remote", "label": "Remote User"}, {"value": "remoterevert", "label": "Remote Revert"}]'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='usermanagement_user_roles',
            value='[{"value": "superadmin", "label": "Super Admin"}, {"value": "teamadmin", "label": "Team Admin"}, {"value": "readonly", "label": "Read Only"}]'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='usermanagement_user_2fa_methods',
            value='[{"value": "totp", "label": "OAUTH OTP"}, {"value": "sms", "label": "SMS OTP"}, {"value": "email", "label": "EMAIL OTP"}]'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='brain_autopair_status',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='brain_pair_token',
            value='N5vQXbjQlQpaCxaC7pwfYb0wsigFpNO1fWdcxfBF4zSxST2C'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='brain_pair_address',
            value='0.0.0.0'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='brain_pair_port',
            value='443'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_user_auto_create',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_user_suspend_inactive',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_user_idle_threshold',
            value='30'
        ))
        
        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_case_insensitive',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_session_timeout',
            value='30'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_lockout_threshold',
            value='5'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_source_lockdown',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_source_lockdown_duration',
            value='15'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_map_domain_to_directory',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_disclaimer_message',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_disclaimer_stage',
            value='before'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_logon_disclaimer_content',
            value='<p>The SIBERAT AI solution provides advanced detection and response capabilities, but cannot guarantee the prevention of all cyber threats. Information is processed in accordance with applicable privacy laws and our Privacy Policy.</p><p>No liability is accepted for damages resulting from its use. Users are responsible for legal compliance and are advised to take additional security measures.</p>'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_display_generator',
            value='off'
        ))


        dbprovider.add(ModelConfiguration(
            attribute='policy_password_show_guidelines',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_weak_detection',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_minimum_lenght',
            value='6'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_maximum_lenght',
            value='64'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_minimum_age',
            value='0'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_maximum_age',
            value='365'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_require_digit',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_require_letter',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_require_symbol',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_allow_username_in_password',
            value='off'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='password_policy_skip_remote_users',
            value='on'
        ))

        dbprovider.add(ModelConfiguration(
            attribute='policy_password_reset_max_attempts',
            value='0'
        ))
        
    except Exception as e:
        service_logger().error(f"after_create: ModelConfiguration error: {e}")
