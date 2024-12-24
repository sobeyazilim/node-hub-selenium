from core.providers import dbprovider
from core.services.serviceLogger import service_logger, service_logger_debug
from core.models.Pydantic.form_credentials import ModelCredentials
from core.classes.class_configuration import class_configuration


class class_credentials:
    def __init__(self):
        self.classbase = "class/credentials"
    def add_credential(self, pydantic_data: ModelCredentials):
        try:
            if class_configuration().return_app_debug_mode():
                service_logger_debug().debug(pydantic_data.dict())
            return 'x'
    
        except Exception as e:
            dbprovider.rollback()
            return False