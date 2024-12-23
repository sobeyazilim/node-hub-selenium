# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, DateTime, event, inspect, Text, func
from sqlalchemy.exc import DBAPIError
from passlib.context import CryptContext
from datetime import datetime, date, time
import pyotp


# providers
from core.providers.dbprovider import dbprovider, dbBase

# class
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceCrypt import service_cryptography
from core.services.serviceLogger import service_logger, service_logger_debug

# definitions
first_public_id = int(class_configuration().return_database_public_id_dict()['PID_ADMINISTRATION_USER_MANAGEMENT_TEAM'])


class ModelAdministrationUserManagementTeam(dbBase):
    __tablename__ = 'administration_usermanagement_team'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    public_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False, unique=True)
    system_defined = Column(Boolean, nullable=True, default=False)
    description = Column(String, nullable=True)

    def __init__(self, **kwargs):
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")

        super().__init__(**kwargs)

    def __repr__(self):
        return f'<Table/Administration/UserManagement/Team -- login name: {self.name}>'

    @staticmethod
    def date_to_string(dt: date) -> str:
        return dt.strftime('%Y-%m-%d') if dt else None

    @staticmethod
    def datetime_to_string(dt: datetime) -> str:
        return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else None

    @staticmethod
    def time_to_string(t: time)  -> str:
        """Convert a time object to a string."""
        return t.strftime('%H:%M:%S')
    
    def as_dict(self) -> dict:
        try:
            """Convert the model instance to a dictionary."""
            columns = {}
            for column in inspect(self).mapper.column_attrs:
                value = getattr(self, column.key, None)
                # If the value is a datetime object, convert to string
                if isinstance(value, datetime):
                    value = self.datetime_to_string(value)
                # If the value is a time object, convert to string
                elif isinstance(value, time):
                    value = self.time_to_string(value)
                # If the value is a date object, convert to string
                elif isinstance(value, date):
                    value = self.date_to_string(value)
                
                columns[column.key] = value
            return columns
        
        except Exception as error:
            service_logger_debug().warning(f"Error model as_dict: {error}")
    
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
            if inspector.has_table(ModelAdministrationUserManagementTeam.__tablename__):

                last_object = dbprovider.query(ModelAdministrationUserManagementTeam) \
                    .order_by(ModelAdministrationUserManagementTeam.public_id.desc()) \
                    .first()
                
                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)

            else:
                # Table does not exist, create it or handle the error accordingly
                service_logger().warning("Table administration_usermanagement_team does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        first_public_id += 1  # Increment the first_public_id
        
        return new_public_id
    
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
            instance = dbprovider.query(ModelAdministrationUserManagementTeam).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    def remove_object(self):
        """Remove object from the database."""
        self._delete()

@event.listens_for(ModelAdministrationUserManagementTeam.__mapper__, 'before_insert')
def value_to_unique(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationUserManagementTeam before_insert triggered")

    # Check for uniqueness of the lowercase team name
    existing_team = dbprovider.query(ModelAdministrationUserManagementTeam).filter(
        func.lower(ModelAdministrationUserManagementTeam.name) == target.name.lower()
    ).first()

    if existing_team:
        raise ValueError("Team name must be unique.")

    return target

@event.listens_for(ModelAdministrationUserManagementTeam.__mapper__, 'before_update')
def value_to_crypt(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationUserManagementTeam before_update triggered")

    return target

@event.listens_for(ModelAdministrationUserManagementTeam, 'load')
def value_to_text(target, context):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationUserManagementTeam query triggered")

# Event listener for after_create
@event.listens_for(ModelAdministrationUserManagementTeam.__table__, 'after_create')  # type: ignore
def aftercreate_model_administration_userManagement_Team(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelAdministrationUserManagementTeam triggered")

    try:

        dbprovider.add(ModelAdministrationUserManagementTeam(
            name='Master',
            system_defined=True,
            description='Default team which manages all teams',
        ))

        dbprovider.add(ModelAdministrationUserManagementTeam(
            name='Network',
            system_defined=True,
            description='Manages network architecture and design',
        ))

        dbprovider.add(ModelAdministrationUserManagementTeam(
            name='System',
            system_defined=True,
            description='Ensuring system security and compliance',
        ))

        dbprovider.add(ModelAdministrationUserManagementTeam(
            name='Security',
            system_defined=True,
            description='Manages security policies and procedures',
        ))

        dbprovider.add(ModelAdministrationUserManagementTeam(
            name='SOC Team',
            system_defined=True,
            description='Monitoring security event logs and alerts',
        ))

    except Exception as e:
        service_logger().error(f"after_create: ModelAdministrationUserManagementTeam error: {e}")
