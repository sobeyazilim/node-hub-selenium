# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, DateTime, Date, event, text, inspect
from sqlalchemy.event import listens_for
from datetime import datetime, date, time

# providers
from core.providers.dbprovider import dbprovider, dbBase

# class
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceCrypt import service_cryptography
from core.services.serviceLogger import service_logger, service_logger_debug

# definitions
first_public_id = int(class_configuration().return_database_public_id_dict()['PID_ADMINISTRATION_USER_MANAGEMENT_DIRECTORY_CONNECTOR'])


class ModelAdministrationUserManagementDirectoryConnector(dbBase):
    __tablename__ = 'administration_usermanagement_directory_connector'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    public_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False, unique=True)
    server_ip_or_name = Column(String, nullable=False)
    replica_server_ip_or_name = Column(String, nullable=True)
    server_port = Column(Integer, nullable=False, default=389)
    base_distinguished_name = Column(String, nullable=False)
    netbios_hostname = Column(String, nullable=False)
    common_name_identifier = Column(String(100), nullable=True, default="sAMAccountName")
    bind_type = Column(String, nullable=True, default="regular")
    bind_username = Column(String, nullable=True)
    bind_password = Column(String, nullable=True)
    secure_connection = Column(Boolean, nullable=True, default=False)
    protocol = Column(String, nullable=True, default="ldaps")
    certificate = Column(String, nullable=True, default="")
    server_identity_check = Column(Boolean, nullable=True, default=False)
    connect_timeout = Column(Integer, nullable=True, default=12)
    readonly = Column(Boolean, nullable=True, default=True)
    enabled = Column(Boolean, nullable=True, default=True)
    description = Column(String, nullable=True)

    def __init__(self, **kwargs):
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")
        super().__init__(**kwargs)

    def __repr__(self):
        columns = {}
        for column in inspect(self).mapper.column_attrs:
            try:
                value = getattr(self, column.key, None)
                if value is not None:
                    columns[column.key] = value
                else:
                    columns[column.key] = "(no value)"
            except AttributeError:
                columns[column.key] = "(no attribute)"
        return str(columns)
    
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
    def generate_public_id():
        global first_public_id
        new_public_id = str(first_public_id+1)

        try:
            # Check if the partition table exists
            inspector = inspect(dbprovider.bind)

            # Check if the partition table exists
            if inspector.has_table(ModelAdministrationUserManagementDirectoryConnector.__tablename__):

                last_object = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector) \
                    .order_by(ModelAdministrationUserManagementDirectoryConnector.public_id.desc()) \
                    .first()
                
                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)

            else:
                # Table does not exist, create it or handle the error accordingly
                service_logger().warning("Table administration_usermanagement_directory_connector does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        first_public_id += 1  # Increment the first_public_id
        
        return new_public_id

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
            instance = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    # Object methods for encryption and decryption of fields
    def return_object_public_id(self):
        """Return public_id"""
        return self.public_id

    def patch_object_bind_username(self, username):
        """Patch bind_username"""
        self.bind_username = username
        self._update()

    def patch_object_bind_password(self, password):
        """Patch bind_password"""
        self.bind_password = password
        self._update()

    def patch_object_certificate(self, certificate):
        """Patch certificate"""
        self.certificate = certificate
        self._update()

    def patch_object_server_identity_check(self, check):
        """Patch server_identity_check"""
        self.server_identity_check = check
        self._update()

    def patch_object_readonly(self, readonly):
        """Patch readonly"""
        self.readonly = readonly
        self._update()

    def patch_object_enabled(self, status):
        self.enabled = status
        self._update()

    def remove_object(self):
        """Remove object from the database."""
        self._delete()

@event.listens_for(ModelAdministrationUserManagementDirectoryConnector.__mapper__, 'before_insert')
@event.listens_for(ModelAdministrationUserManagementDirectoryConnector.__mapper__, 'before_update')
def value_to_crypt( mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationUserManagementDirectoryConnector before_insert/update triggered")

    if not hasattr(target, '_encrypted'):
        target._encrypted = False

    # encrypt fields
    if not target._encrypted:
        if target.server_ip_or_name:
            setattr(target, 'server_ip_or_name', target.text_to_crypt(target.server_ip_or_name))

        if target.replica_server_ip_or_name:
            setattr(target, 'replica_server_ip_or_name', target.text_to_crypt(target.replica_server_ip_or_name))

        if target.base_distinguished_name:
            setattr(target, 'base_distinguished_name', target.text_to_crypt(target.base_distinguished_name))

        if target.netbios_hostname:
            setattr(target, 'netbios_hostname', target.text_to_crypt(target.netbios_hostname))

        if target.bind_username:
            setattr(target, 'bind_username', target.text_to_crypt(target.bind_username))

        if target.bind_password:
            setattr(target, 'bind_password', target.text_to_crypt(target.bind_password))
        
        target._encrypted = True

    return target

@event.listens_for(ModelAdministrationUserManagementDirectoryConnector, 'load')
def value_to_text(target, context):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationUserManagementDirectoryConnector query triggered")

    if target.server_ip_or_name:
        target.server_ip_or_name = target.crypt_to_text(target.server_ip_or_name)

    if target.replica_server_ip_or_name:
        target.replica_server_ip_or_name = target.crypt_to_text(target.replica_server_ip_or_name)

    if target.base_distinguished_name:
        target.base_distinguished_name = target.crypt_to_text(target.base_distinguished_name)

    if target.netbios_hostname:
        target.netbios_hostname = target.crypt_to_text(target.netbios_hostname)

    if target.bind_username:
        target.bind_username = target.crypt_to_text(target.bind_username)

    if target.bind_password:
        target.bind_password = target.crypt_to_text(target.bind_password)

@event.listens_for(ModelAdministrationUserManagementDirectoryConnector.__table__, 'after_create')
def aftercreate_model_administration_userManagement_Directory_Connector(*args, **kwargs):
    """Insert initial elements into table after created"""
    """Handle post-table creation actions"""
    service_logger().info("after_create: ModelAdministrationUserManagementDirectoryConnector triggered")

    try:
        dbprovider.add(ModelAdministrationUserManagementDirectoryConnector(
            name='DC',
            server_ip_or_name='0.0.0.0',
            replica_server_ip_or_name='0.0.0.0',
            server_port=636,
            protocol="ldaps",
            base_distinguished_name='dc=sobe,dc=local',
            netbios_hostname='sobe',
            common_name_identifier='cn',
            bind_type='regular',
            bind_username='administrator',
            bind_password='',
            secure_connection=True,
            description='Test DC',
            connect_timeout=5,
            enabled=False
        ))
        
    except Exception as e:
        service_logger().error(f"after_create: ModelAdministrationUserManagementDirectoryConnector error: {e}")