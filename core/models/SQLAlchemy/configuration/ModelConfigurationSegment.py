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
first_public_id = int(class_configuration().return_database_public_id_dict()['PID_CONFIGURATION_SEGMENTS'])

class ModelConfigurationSegment(dbBase):
    __tablename__ = 'segment'
    __table_args__ = {'quote': False, 'extend_existing': True}

    # Define columns
    id = Column(Integer, primary_key=True)
    public_id = Column(String, nullable=False, unique=True)
    segment_name = Column(String, nullable=False, unique=True)
    segment_hosts = Column(Text, nullable=False)
    system_defined = Column(Boolean, nullable=True, default=False)

    def __init__(self, **kwargs):
        # Automatically generate public_id if not provided
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")

        super().__init__(**kwargs)

    def __repr__(self):
        return f'<Table/Configuration/Segment -- name: {self.segment_name}>'

    
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
        """Generate a new public ID for the segment."""
        global first_public_id
        new_public_id = str(first_public_id + 1)

        try:
            inspector = inspect(dbprovider.bind)

            if inspector.has_table(ModelConfigurationSegment.__tablename__):
                last_object = dbprovider.query(ModelConfigurationSegment) \
                    .order_by(ModelConfigurationSegment.public_id.desc()) \
                    .first()
                
                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)
            else:
                service_logger().warning("Table segment does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        first_public_id += 1  # Increment the global counter
        return new_public_id
    
    def _update(self):
        """Update the current object in the database."""
        try:
            dbprovider.merge(self)
            dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _update: {e}")
            dbprovider.rollback()

    def _delete(self):
        """Delete the current object from the database."""
        try:
            instance = dbprovider.query(ModelConfigurationSegment).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    def remove_object(self):
        """Public method to remove the object from the database."""
        self._delete()

@event.listens_for(ModelConfigurationSegment.__mapper__, 'before_insert')
def value_to_unique(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelConfigurationSegment before_insert triggered")

    # Check for uniqueness of the lowercase team name
    existing_team = dbprovider.query(ModelConfigurationSegment).filter(
        func.lower(ModelConfigurationSegment.segment_name) == target.segment_name.lower()
    ).first()

    if existing_team:
        raise ValueError("Segment name must be unique.")

    return target

@event.listens_for(ModelConfigurationSegment.__mapper__, 'before_update')
def value_to_crypt(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelConfigurationSegment before_update triggered")

    return target

@event.listens_for(ModelConfigurationSegment, 'load')
def value_to_text(target, context):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelConfigurationSegment query triggered")

# Event listener for after_create
@event.listens_for(ModelConfigurationSegment.__table__, 'after_create')  # type: ignore
def aftercreate_model_segment(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelConfigurationSegment triggered")

    try:

        dbprovider.add(ModelConfigurationSegment(
            segment_name='Private-use networks',
            segment_hosts='192.168.0.0/16,172.16.0.0/12,10.0.0.0/8',
            system_defined=True,
        ))

        dbprovider.add(ModelConfigurationSegment(
            segment_name='LinkLocal',
            segment_hosts='169.254.0.0/16',
            system_defined=True,
        ))

        dbprovider.add(ModelConfigurationSegment(
            segment_name='Multicast',
            segment_hosts='224.0.0.0/4',
            system_defined=True,
        ))

        dbprovider.add(ModelConfigurationSegment(
            segment_name='Loopback',
            segment_hosts='127.0.0.0/8',
            system_defined=True,
        ))

        dbprovider.add(ModelConfigurationSegment(
            segment_name='Bogon TEST-NETs',
            segment_hosts='198.51.100.0/24, 192.0.2.0/24, 203.0.113.0/24',
            system_defined=True,
        ))

    except Exception as e:
        service_logger().error(f"after_create: ModelConfigurationSegment error: {e}")
