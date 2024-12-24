from datetime import datetime
import pytz

# schemas
from core.schemas import *

# providers
from core.providers.public_id import database_public_id_dict

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
    
    def return_app_policy_login_counter(self)  -> int:
        return 5

    def return_database_sqlalchemy_database_uri(self) -> str:
        return database_sqlalchemy_database_uri
    
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

    def return_system_timezones(self) -> list:
        return pytz.all_timezones
