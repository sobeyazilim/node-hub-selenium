from time import  localtime, strftime
from fastapi import  Request
from datetime import datetime
from sqlalchemy.exc import DBAPIError
import pytz
import json

# models
from core.models.SQLAlchemy.configuration.ModelConfiguration import ModelConfiguration

# providers
from core.providers.dbprovider import dbprovider

# schemas
from core.schemas import *

# providers
from core.providers.public_id import database_public_id_dict
from core.providers.dryrun import dryrun_events_json

# services
from core.services.serviceLogger import service_logger, service_logger_debug

class class_configuration:
    def __init__(self):
        self.classbase = "class/configuration"

    def return_app_version(self) -> str:
        return app_version

    def return_app_title(self) -> str:
        return app_title

    def return_app_summary(self) -> str:
        return app_summary

    def return_app_company(self) -> str:
        return app_company

    def return_app_contact_name(self) -> str:
        return app_contact_name

    def return_app_contact_email(self) -> str:
        return app_contact_email

    def return_app_terms_of_service(self) -> str:
        return app_terms_of_service

    def return_app_description(self) -> str:
        return app_description

    def return_app_build_number(self) -> str:
        return datetime.now().timestamp()

    def return_app_login_timeout(self) -> int:
        return app_login_timeout
    
    def return_app_jwt_token_label(self) -> str:
        return app_jwt_token_label

    def return_app_jwt_key(self) -> str:
        return app_jwt_key

    def return_app_jwt_private_key(self):
        return app_jwt_private_key
    
    def return_app_jwt_public_key(self):
        return app_jwt_public_key
    
    def return_app_jwt_symetric_algorithm(self) -> str:
        return app_jwt_symetric_algorithm
    
    def return_app_jwt_asymetric_algorithm(self) -> str:
        return app_jwt_asymetric_algorithm
    
    def return_app_secret_key(self) -> str:
        return app_secret_key

    def return_app_fernet_private_key(self) -> str:
        return app_fernet_private_key

    def return_app_memory_cache_size(self) -> int:
        return app_memory_cache_size
    
    def return_app_debug_mode(self) -> bool:
        return app_debug_mode

    def return_app_log_path(self) -> str:
        return app_log_path

    def return_app_stream_mode(self) -> bool:
        return app_stream_mode
    
    def return_app_scouting_container_url(self)  -> str:
        return app_scouting_container_url
    
    def return_app_policy_login_counter(self)  -> int:
        return 5
    
    def return_websocket_server_key(self) -> str:
        return websocket_server_key
    
    def return_websocket_database_insert_batch_size(self) -> int:
        return websocket_database_insert_batch_size

    def return_websocket_dryrun_events(self):
        return dryrun_events_json

    def return_database_sqlalchemy_database_uri(self) -> str:
        return database_sqlalchemy_database_uri
    
    def return_database_retention_table_name(self) -> str:
        return database_retention_table_name

    def return_database_store_incidents(self) -> bool:
        return database_store_incidents
    
    def return_database_retention_period_days(self) -> int:
        return database_retention_period_days

    def return_database_max_allowed_table_size(self) -> int:
        return database_max_allowed_table_size
    
    def return_database_portion_of_records_to_delete(self) -> int:
        return database_portion_of_records_to_delete

    def return_database_identifier_to_delete_records(self) -> str:
        return database_identifier_to_delete_records

    def return_database_pool_size(self) -> int:
        return database_pool_size

    def return_database_max_overflow(self) -> int:
        return database_max_overflow
    
    def return_database_public_id_dict(self) -> dict:
        return database_public_id_dict

    def return_map_switched_type(self) -> str:
        return map_switched_type

    def return_map_websocket_channel_uri(self) -> str:
        return map_websocket_channel_uri
    
    def return_map_default_tile_name(self) -> str:
        return map_default_tile_name
    
    def return_map_applications(self) -> list:
        return map_applications

    def return_system_timezones(self) -> list:
        return pytz.all_timezones
        
    def return_configuration_full(self) -> dict:
        """Return all attributes and values as a dictionary, handling JSON values."""
        results = dbprovider.query(ModelConfiguration).all()

        data = {}

        # convert single dict
        for obj in results:
            data[obj.attribute] = obj.value

        # Convert the string representation of the list to an actual list
        if 'system_ntpentity_servers' in data:
            data['system_ntpentity_servers'] = json.loads(data['system_ntpentity_servers'])

        # Convert the string representation of the list to an actual list
        if 'rinspection_scope_segments' in data:
            data['rinspection_scope_segments'] = json.loads(data['rinspection_scope_segments'])

        # Convert the string representation of the list to an actual list
        if 'snmp_accesslist_hosts' in data:
            data['snmp_accesslist_hosts'] = json.loads(data['snmp_accesslist_hosts'])

        # Convert the string representation of the list to an actual list
        if 'usermanagement_user_types' in data:
            data['usermanagement_user_types'] = json.loads(data['usermanagement_user_types'])

        # Convert the string representation of the list to an actual list
        if 'usermanagement_user_roles' in data:
            data['usermanagement_user_roles'] = json.loads(data['usermanagement_user_roles'])

        # Convert the string representation of the list to an actual list
        if 'usermanagement_user_2fa_methods' in data:
            data['usermanagement_user_2fa_methods'] = json.loads(data['usermanagement_user_2fa_methods'])

        # Convert the string representation of the list to an actual list
        if 'log_syslog_servers' in data:
            data['log_syslog_servers'] = json.loads(data['log_syslog_servers'])
            data['log_syslog_servers_size'] = len(data['log_syslog_servers'])

        else:
            data['log_syslog_servers'] = json.loads('[]')
            data['log_syslog_servers_size'] = 0


        # if class_configuration().return_app_debug_mode():
        #     service_logger_debug().debug(data)

        return data
    
    def update_configuration(self, pydantic_data, auto_create: bool = True, crypted: bool = False) -> bool:
        try:

            if class_configuration().return_app_debug_mode():
                service_logger_debug().debug(pydantic_data)

            # iterate over the Pydantic data and create ModelConfiguration instances
            for key, value in pydantic_data.dict().items():
                
                # Check if value is a dict, list, or tuple that should be serialized to JSON
                if isinstance(value, (dict, list, tuple)):
                    added_value = json.dumps(value)
                else:
                    # Use str() for simple types (str, int, float, etc.)
                    added_value= str(value)

                # text items
                model_config = dbprovider.query(ModelConfiguration).filter_by(attribute=key).first()
                
                if model_config:
                    model_config.value = added_value
                else:
                    if auto_create:
                        # create new record
                        model_config = ModelConfiguration(
                            attribute=key,
                            value=added_value,  # convert value to string
                            crypted=crypted
                        )
                        dbprovider.add(model_config)

            dbprovider.commit()

            return True
    
        except Exception as error:
            service_logger().critical(f"*** Configuration update error: {error} ")
            dbprovider.rollback()
            
            return False
