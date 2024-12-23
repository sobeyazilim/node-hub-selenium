# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, Date, DateTime, event, inspect, Text, Time
from sqlalchemy.exc import DBAPIError
from passlib.context import CryptContext
from datetime import datetime, time, date
import pyotp
import json
import pytz
import ipaddress

# providers
from core.providers.dbprovider import dbprovider, dbBase

# class
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceCrypt import service_cryptography
from core.services.serviceLogger import service_logger, service_logger_debug

# definitions
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
first_public_id = int(class_configuration().return_database_public_id_dict()['PID_ADMINISTRATION_USER_MANAGEMENT_USER'])


class ModelAdministrationUserManagementUser(dbBase):
    __tablename__ = 'administration_usermanagement_user'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    public_id = Column(String, nullable=False, unique=True)
    login_name = Column(String, nullable=False, unique=True)
    display_name = Column(String, nullable=False, unique=False)
    user_type = Column(String, nullable=False, default="local")
    email = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    password = Column(String, nullable=True)
    team = Column(Text, nullable=True, default='11000000000001')
    role = Column(String, nullable=False, default="readonly")
    directory_source = Column(String, nullable=True)
    directory_source_dn = Column(String, nullable=True, unique=True)
    enabled = Column(Boolean, nullable=False, default=True)
    authentication_profile = Column(String, nullable=True, default='13000000000001')
    authentication_challenge_last = Column(DateTime, nullable=True)
    authentication_oauth_confirm_stat = Column(Boolean, nullable=True, default=False)
    authentication_oauth_secret = Column(String, nullable=True, default=None)
    cannot_change_password = Column(Boolean,nullable = True,unique = False,default = False)
    change_password_at_next_login = Column(Boolean,nullable = True,unique = False,default = False)
    password_never_expires = Column(Boolean,nullable = True,unique = False,default = False)
    password_reset_datetime = Column(DateTime,nullable = True,unique = False)
    suspend_lock = Column(Boolean,nullable = True,unique = False,default = False)
    suspend_lock_until_date = Column(Date,nullable = True,unique = False)
    counter_lock = Column(Boolean,nullable = True,unique = False,default = False)
    counter = Column(Integer,nullable = True,unique = False,default = 0)
    automated_account_expiry = Column(Boolean,nullable = True,unique = False,default = False)
    automated_account_expiry_date = Column(Date,nullable = True,unique = False)
    time_based_access_control = Column(Boolean, nullable = True, unique = False, default = False)
    time_based_access_control_timezone = Column(String, nullable=True, default='Turkey')
    time_based_access_control_start = Column(Time, nullable=True, default=time(9, 0))
    time_based_access_control_end = Column(Time, nullable=True, default=time(17, 0))
    time_based_access_control_days = Column(Text, nullable=True, default=json.dumps(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]))
    trusted_host_access_control = Column(Boolean, nullable=False, default=False)
    trusted_hosts = Column(Text, nullable=False, default='10.0.0.0/8,172.16.0.0/12,192.168.0.0/16')
    last_login_datetime = Column(DateTime, nullable=True)
    last_login_ipaddress = Column(String, nullable=True)
    system_defined = Column(Boolean, nullable=True, default=False)
    description = Column(String, nullable=True)

    def __init__(self, **kwargs):
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")

        if 'authentication_oauth_secret' not in kwargs:
            try:
                kwargs['authentication_oauth_secret'] = self.generate_oauth_secret()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")

        super().__init__(**kwargs)

    def __repr__(self):
        return f'<Table/Administration/UserManagement/User -- login name: {self.login_name}>'

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
    def hash_password(value):
        try:
            return pwd_context.hash(value)
    
        except Exception as e:
            service_logger().warning(f"Error model password_hash: {e}")
            return None  # Return None or handle error as needed

    @staticmethod
    def generate_public_id():
        global first_public_id
        new_public_id = str(first_public_id+1)

        try:
            # Check if the partition table exists
            inspector = inspect(dbprovider.bind)

            # Check if the partition table exists
            if inspector.has_table(ModelAdministrationUserManagementUser.__tablename__):

                last_object = dbprovider.query(ModelAdministrationUserManagementUser) \
                    .order_by(ModelAdministrationUserManagementUser.public_id.desc()) \
                    .first()
                
                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)

            else:
                # Table does not exist, create it or handle the error accordingly
                service_logger().warning("Table administration_usermanagement_user does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        first_public_id += 1  # Increment the first_public_id
        
        return new_public_id
    
    @staticmethod
    def generate_oauth_secret():
        """Generate oauth secret"""
        oauth_secret = pyotp.random_base32()
        return oauth_secret
    
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
            instance = dbprovider.query(ModelAdministrationUserManagementUser).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    def patch_object_password(self, password):
        self.password = password
        self._update()

    def verify_object_password(self, plain_password):
        return pwd_context.verify(plain_password, self.password)

    def patch_object_trusted_host_access_control(self, status):
        self.trusted_host_access_control = status
        self._update()

    def return_object_authentication_oauth_secret_formated(self, hostname: str = None, domain: str = "sobeyazilim.com.tr"):
        plaintext = self.authentication_oauth_secret
        if hostname:
            return pyotp.TOTP(plaintext).provisioning_uri(name=f'({self.login_name}) @{hostname}.{domain}', issuer_name=f'MYSOBE')
        else:
            return pyotp.TOTP(plaintext).provisioning_uri(name=f'({self.login_name}) @{domain}', issuer_name='MYSOBE')
        
    def patch_object_authentication_oauth_secret(self, secret):
        self.authentication_oauth_secret = secret
        self._update()

    def reset_object_authentication_oauth_secret(self):
        self.authentication_oauth_secret = pyotp.random_base32()
        self.authentication_oauth_confirm_stat = False
        self._update()

    def verify_object_authentication_oauth_secret(self, code_entered):
        totp_identifier = pyotp.TOTP(self.authentication_oauth_secret)
        return totp_identifier.verify(code_entered)
    
    # object: suspend_lock and suspend_lock_until_date
    def verify_object_suspend_lock(self):
        """ Return suspend_lock """
        if self.suspend_lock_until_date:
            if datetime.now().date() > self.suspend_lock_until_date:
                self.suspend_lock = False
                self.suspend_lock_until_date = None
                self._update()
                return False
            
        return self.suspend_lock

    def patch_object_suspend_lock(self, status):
        """ patch suspend_lock """
        self.suspend_lock = status
        self._update()

    def patch_object_suspend_lock_until_date(self, enddatetime):
        """ patch suspend_lock_until_date """
        self.suspend_lock_until_date = enddatetime
        self._update()

    # object: update counter_lock status
    def patch_object_counter_lock(self, status):
        """ patch counter_lock """
        if not status:
            self.counter = 0

        self.counter_lock = status
        self._update()

    def check_object_counter_lock(self):
        if self.counter >= class_configuration().return_app_policy_login_counter():
            self.counter_lock = True
            self._update()

    def reset_object_counter_lock(self):
        """ patch counter_lock """
        self.counter = 0
        self.counter_lock = False
        self._update()

    # object: counter
    def countup_object_counter(self):
        """ countup counter """
        self.counter = self.counter + 1
        self._update()

    # object: automated_account_expiry
    def patch_object_automated_account_expiry(self, status):
        """ patch automated_account_expiry """
        self.automated_account_expiry = status
        self._update()

    def verify_object_expired(self):
        """ verify expired  """
        if self.automated_account_expiry:
            if datetime.now().date() > self.automated_account_expiry_date:
                return True
        
        return False
    
    # object: automated_account_expiry_datetime    
    def patch_object_automated_account_expiry_date(self, whenexpire):
        """ patch automated_account_expiry_date """
        self.automated_account_expiry_date = whenexpire
        self._update()

    # object: enabled
    def patch_object_enabled(self, status):
        self.enabled = status
        self._update()

    def patch_object_last_login_datetime(self):
        self.last_login_datetime = datetime.now()
        self._update()

    def patch_object_last_login_ipaddress(self, ipaddress):
        self.last_login_ipaddress = ipaddress
        self._update()

    def return_object_status(self):
        if not self.enabled:
            return "disabled"
        elif self.automated_account_expiry and datetime.now().date() > self.automated_account_expiry_date:
            return "expired"
        elif self.suspend_lock:
            return "suspended"
        elif self.counter_lock:
            return "locked"
        elif self.last_login_ipaddress:
            return "active"
        else:
            return "created"

    def verify_object_trusted_login(self, source_ip):
        # Convert the input IP address string to an ipaddress object
        ip = ipaddress.ip_address(source_ip.strip())
        trusted_networks = [ipaddress.ip_network(host.strip()) for host in self.trusted_hosts.split(',')]
        
        # Check if the IP address is in any of the trusted networks
        for network in trusted_networks:
            if ip in network:
                return True
        
        return False
        
    # object: verify account status
    def verify_user_able_to_login(self, source_ip):
        # check user disabled
        if not self.enabled:
            return False # User cannot log in
        
        # check user locked
        if self.counter_lock:
            return False # User cannot log in
        
        # check user suspended
        if self.verify_object_suspend_lock():
            return False # User cannot log in
        
        # check user expired
        if self.verify_object_expired():
            return False # User cannot log in

        # check user has time based access policy        
        if self.time_based_access_control:
            # Get the current time in the user's timezone
            user_tz = pytz.timezone(self.time_based_access_control_timezone)
            current_time = datetime.now(user_tz).time()
            current_day = datetime.now(user_tz).strftime('%A')  # Get the current day name
        
            # Check if the current time is within the allowed access time
            if self.time_based_access_control_start <= current_time <= self.time_based_access_control_end:
                # Check if the current day is in the allowed days
                allowed_days = self.time_based_access_control_days
                if allowed_days and current_day not in allowed_days:
                    return False  # User can log in
            
            # Handle overnight access (e.g., 18:00 to 02:00)
            elif self.time_based_access_control_start > self.time_based_access_control_end:
                if current_time >= self.time_based_access_control_start or current_time <= self.time_based_access_control_end:
                    # Check if the current day is in the allowed days
                    allowed_days = self.time_based_access_control_days
                    if allowed_days and current_day not in allowed_days:
                        return False  # User can log in
                else:
                    return False  # User cannot log in
            else:
                return False  # User cannot log in


         # Check if the user has a trusted login
        if self.trusted_host_access_control:
            if not self.verify_object_trusted_login(source_ip):
                return False # User cannot log in

        return True

    def why_not_able_to_login(self, source_ip):
        reason = ''
        # check user disabled
        if not self.enabled:
            reason = 'Account has been disabled'

        # check user locked
        if self.counter_lock:
            reason = 'Account has been locked'

        # check user suspend
        if self.verify_object_suspend_lock():
            reason = 'Account has been suspended'

        # check user expire
        if self.verify_object_expired():
            reason = 'Account has been expired'

        # check user has time based access policy        
        if self.time_based_access_control:
            # Get the current time in the user's timezone
            user_tz = pytz.timezone(self.time_based_access_control_timezone)
            current_time = datetime.now(user_tz).time()
            current_day = datetime.now(user_tz).strftime('%A')  # Get the current day name
        
            # Check if the current time is within the allowed access time
            if self.time_based_access_control_start <= current_time <= self.time_based_access_control_end:
                # Check if the current day is in the allowed days
                allowed_days = self.time_based_access_control_days
                if allowed_days and current_day not in allowed_days:
                    reason = 'Account logon day of week restriction violation'

            # Handle overnight access (e.g., 18:00 to 02:00)
            elif self.time_based_access_control_start > self.time_based_access_control_end:
                if current_time >= self.time_based_access_control_start or current_time <= self.time_based_access_control_end:
                    # Check if the current day is in the allowed days
                    allowed_days = self.time_based_access_control_days
                    if allowed_days and current_day not in allowed_days:
                        reason = 'Account logon day of week restriction violation'
                else:
                    reason = 'Account logon time range restriction violation'
            else:
                reason = 'Account logon time range restriction violation'

         # Check if the user has a trusted login
        if self.trusted_host_access_control:
            if not self.verify_object_trusted_login(source_ip):
                reason = 'Account logon trusted host violation'

        return reason

    def remove_object(self):
        """Remove object from the database."""
        self._delete()

@event.listens_for(ModelAdministrationUserManagementUser.__mapper__, 'before_insert')
@event.listens_for(ModelAdministrationUserManagementUser.__mapper__, 'before_update')
def value_to_crypt(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationUserManagementUser before_insert/update triggered")

    if not hasattr(target, '_encrypted'):
        target._encrypted = False

    # encrypt fields
    if not target._encrypted:
        if target.display_name:
            setattr(target, 'display_name', target.text_to_crypt(target.display_name))
        if target.email:
            setattr(target, 'email', target.text_to_crypt(target.email))
        if target.phone:
            setattr(target, 'phone', target.text_to_crypt(target.phone))
        if target.authentication_oauth_secret:
            setattr(target, 'authentication_oauth_secret', target.text_to_crypt(target.authentication_oauth_secret))
        if target.description:
            setattr(target, 'description', target.text_to_crypt(target.description))
    
        target._encrypted = True

    # Check if password is already hashed using bcrypt
    if target.password and not target.password.startswith('$2b$'):
        target.password = target.hash_password(target.password)

    if target.time_based_access_control_days:
        # Check if the attribute is not already a JSON string
        if not isinstance(target.time_based_access_control_days, str):
            # Serialize the attribute to JSON
            setattr(target, 'time_based_access_control_days', json.dumps(target.time_based_access_control_days))
    
    return target

@event.listens_for(ModelAdministrationUserManagementUser, 'load')
def value_to_text(target, context):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationUserManagementUser query triggered")

    if target.display_name:
        target.display_name = target.crypt_to_text(target.display_name)

    if target.email:
        target.email = target.crypt_to_text(target.email)

    if target.phone:
        target.phone = target.crypt_to_text(target.phone)

    if target.authentication_oauth_secret:
        target.authentication_oauth_secret = target.crypt_to_text(target.authentication_oauth_secret)

    if target.description:
        target.description = target.crypt_to_text(target.description)

    if target.time_based_access_control_days:
        # Convert the JSON string to a list
        target.time_based_access_control_days = json.loads(target.time_based_access_control_days)

# Event listener for after_create
@event.listens_for(ModelAdministrationUserManagementUser.__table__, 'after_create')  # type: ignore
def aftercreate_model_administration_userManagement_User(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelAdministrationUserManagementUser triggered")

    try:

        dbprovider.add(ModelAdministrationUserManagementUser(
            login_name='master',
            display_name = 'Master',
            role='superadmin',
            password='6OcWt7vHoiGLo3eM6L0VIfHhq',
            system_defined=True,
            description='Master User',
        ))

        dbprovider.add(ModelAdministrationUserManagementUser(
            login_name='admin',
            display_name = 'Administrator',
            role='superadmin',
            password='sobeadmin',
            system_defined=True,
            description='Local Admin'
        ))

        dbprovider.add(ModelAdministrationUserManagementUser(
            login_name='manager',
            display_name = 'Manager',
            role='teamadmin',
            password='sobeadmin',
            system_defined=False,
            description='Team Admin'
        ))
        
        dbprovider.add(ModelAdministrationUserManagementUser(
            login_name='monitor',
            display_name = 'Monitor',
            password='sobemonitor',
            system_defined=True,
            description='Read-Only User',
        ))

    except Exception as e:
        service_logger().error(f"after_create: ModelAdministrationUserManagementUser error: {e}")
