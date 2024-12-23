# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, DateTime, event, inspect, Text
from sqlalchemy.exc import DBAPIError
from passlib.context import CryptContext
from datetime import datetime
import pyotp


# providers
from core.providers.dbprovider import dbprovider, dbBase

# class
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceCrypt import service_cryptography
from core.services.serviceLogger import service_logger, service_logger_debug

# definitions
first_public_id = int(class_configuration().return_database_public_id_dict()['PID_CYBERPOT_DECOYS'])


class ModelCyberPotDecoys(dbBase):
    __tablename__ = 'cyberpot_decoys'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    public_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False, unique=True)
    autostart = Column(Boolean, nullable=True, default=True)
    tool = Column(Boolean, nullable=True, default=False)
    enabled = Column(Boolean, nullable=False, default=True)
    system_defined = Column(Boolean, nullable=True, default=True)
    description = Column(String, nullable=True)

    def __init__(self, **kwargs):
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")

        super().__init__(**kwargs)

    def __repr__(self):
        return f'<Table/Cyberpot/Decoys -- name: {self.name}>'

    def as_dict(self) -> dict:
        """Convert the model instance to a dictionary."""
        columns = {}
        for column in inspect(self).mapper.column_attrs:
            value = getattr(self, column.key, None)
            if isinstance(value, DateTime):
                value = self.datetime_to_string(value)
            columns[column.key] = value
        return columns

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
    
    @staticmethod
    def generate_public_id():
        global first_public_id
        new_public_id = str(first_public_id+1)

        try:
            # Check if the partition table exists
            inspector = inspect(dbprovider.bind)

            # Check if the partition table exists
            if inspector.has_table(ModelCyberPotDecoys.__tablename__):

                last_object = dbprovider.query(ModelCyberPotDecoys) \
                    .order_by(ModelCyberPotDecoys.public_id.desc()) \
                    .first()
                
                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)

            else:
                # Table does not exist, create it or handle the error accordingly
                service_logger().warning("Table cyberpot_decoys does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        first_public_id += 1  # Increment the first_public_id
        
        return new_public_id
    
    @staticmethod
    def generate_totp_secret():
        """Generate totp secret"""
        totp_secret = pyotp.random_base32()
        return totp_secret
    
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
            instance = dbprovider.query(ModelCyberPotDecoys).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    def patch_object_enabled(self, status):
        self.enabled = status
        self._update()

    def remove_object(self):
        """Remove object from the database."""
        self._delete()

@event.listens_for(ModelCyberPotDecoys.__mapper__, 'before_insert')
@event.listens_for(ModelCyberPotDecoys.__mapper__, 'before_update')
def value_to_crypt(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelCyberPotDecoys before_insert/update triggered")

    return target

@event.listens_for(ModelCyberPotDecoys, 'load')
def value_to_text(target, context):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelCyberPotDecoys query triggered")

# Event listener for after_create
@event.listens_for(ModelCyberPotDecoys.__table__, 'after_create')  # type: ignore
def aftercreate_model_cyberpot_decoys(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelCyberPotDecoys triggered")

    try:

        predefined_decoys = [
            {"decoy_name": "adbhoney", "decoy_description": "ADBHoney is a low-interaction honeypot designed for Android Debug Bridge over TCP/IP.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "ciscoasa", "decoy_description": "CiscoASA is a honeypot that mimics a Cisco ASA device.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "conpot", "decoy_description": "Conpot is a low-interaction honeypot that simulates industrial control systems.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "cowrie", "decoy_description": "Cowrie is a medium-interaction honeypot that simulates an SSH server.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "ddospot", "decoy_description": "Ddospot is a honeypot that detects and responds to DDoS attacks.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "dicompot", "decoy_description": "Dicompot is a honeypot that simulates a DICOM server.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "dionaea", "decoy_description": "Dionaea is a low-interaction honeypot that simulates a variety of services.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "heralding", "decoy_description": "Heraldling is a honeypot that simulates a Windows system.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "honeytrap", "decoy_description": "Honeytrap is a low-interaction honeypot that simulates a variety of services.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "redishoneypot", "decoy_description": "Redishoneypot is a honeypot that simulates a Redis server.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "sentrypeer", "decoy_description": "Sentrypeer is a honeypot that simulates a SentryPeer server.", "decoy_autostart": False, "decoy_enabled": False, "tool": False},
            {"decoy_name": "spiderfoot", "decoy_description": "Spiderfoot is an open-source intelligence gathering tool.", "decoy_autostart": True, "decoy_enabled": True, "tool": True},
            {"decoy_name": "suricata", "decoy_description": "Suricata is a network-based intrusion detection system.", "decoy_autostart": False, "decoy_enabled": False, "tool": False}
        ]

        for decoy in predefined_decoys:
            dbprovider.add(ModelCyberPotDecoys(
                name=decoy["decoy_name"],
                system_defined=True,
                description=decoy["decoy_description"],
                tool=decoy.get("tool", False),  # default to False
                autostart=decoy.get("decoy_autostart", False),  # default to False if key doesn't exist
                enabled=decoy.get("decoy_enabled", False),  # default to False if key doesn't exist
            ))

    except Exception as e:
        service_logger().error(f"after_create: ModelCyberPotDecoys error: {e}")
