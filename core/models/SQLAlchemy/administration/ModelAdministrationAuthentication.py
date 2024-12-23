# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, DateTime, event, inspect, Text, func
from sqlalchemy.exc import DBAPIError
from passlib.context import CryptContext
from datetime import datetime, date, time
import json

# providers
from core.providers.dbprovider import dbprovider, dbBase

# class
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceCrypt import service_cryptography
from core.services.serviceLogger import service_logger, service_logger_debug

# definitions
first_public_id_authentication_profile = int(class_configuration().return_database_public_id_dict()['PID_ADMINISTRATION_AUTHENTICATION_PROFILE'])
first_public_id_authentication_secquestion = int(class_configuration().return_database_public_id_dict()['PID_ADMINISTRATION_AUTHENTICATION_SECURITY_QUESTION'])


class ModelAdministrationAuthenticationProfile(dbBase):
    __tablename__ = 'administration_authentication_profile'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    public_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False, unique=True)
    challanges = Column(Text, nullable=True, default=json.dumps([]))
    pass_through_duration = Column(Integer, nullable=True, default=15)
    system_defined = Column(Boolean, nullable=True, default=False)
    questions = Column(Text, nullable=True, default=json.dumps([]))
    description = Column(Text, nullable=True)

    def __init__(self, **kwargs):
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")

        super().__init__(**kwargs)

    def __repr__(self):
        return f'<Table/Administration/AuthenticationProfile -- profile name: {self.name}>'

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
        global first_public_id_authentication_profile
        new_public_id = str(first_public_id_authentication_profile+1)

        try:
            # Check if the partition table exists
            inspector = inspect(dbprovider.bind)

            # Check if the partition table exists
            if inspector.has_table(ModelAdministrationAuthenticationProfile.__tablename__):

                last_object = dbprovider.query(ModelAdministrationAuthenticationProfile) \
                    .order_by(ModelAdministrationAuthenticationProfile.public_id.desc()) \
                    .first()
                
                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)

            else:
                # Table does not exist, create it or handle the error accordingly
                service_logger().warning("Table administration_authentication_profile does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        first_public_id_authentication_profile += 1  # Increment the first_public_id_authentication_profile
        
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
            instance = dbprovider.query(ModelAdministrationAuthenticationProfile).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    def remove_object(self):
        """Remove object from the database."""
        self._delete()

@event.listens_for(ModelAdministrationAuthenticationProfile.__mapper__, 'before_insert')
def value_to_unique(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationAuthenticationProfile before_insert triggered")

    # Check for uniqueness of the lowercase team name
    existing_profile = dbprovider.query(ModelAdministrationAuthenticationProfile).filter(
        func.lower(ModelAdministrationAuthenticationProfile.name) == target.name.lower()
    ).first()

    if existing_profile:
        raise ValueError("Profile name must be unique.")

    if target.challanges:
        # Check if the attribute is not already a JSON string
        if not isinstance(target.challanges, str):
            # Serialize the attribute to JSON
            setattr(target, 'challanges', json.dumps(target.challanges))
    
    if target.questions:
        # Check if the attribute is not already a JSON string
        if not isinstance(target.questions, str):
            # Serialize the attribute to JSON
            setattr(target, 'questions', json.dumps(target.questions))
    
    return target

@event.listens_for(ModelAdministrationAuthenticationProfile.__mapper__, 'before_update')
def value_to_crypt(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationAuthenticationProfile before_update triggered")

    if target.challanges:
        # Check if the attribute is not already a JSON string
        if not isinstance(target.challanges, str):
            # Serialize the attribute to JSON
            setattr(target, 'challanges', json.dumps(target.challanges))

    if target.questions:
        # Check if the attribute is not already a JSON string
        if not isinstance(target.questions, str):
            # Serialize the attribute to JSON
            setattr(target, 'questions', json.dumps(target.questions))

    return target

@event.listens_for(ModelAdministrationAuthenticationProfile, 'load')
def value_to_text(target, context):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationAuthenticationProfile query triggered")

    if target.challanges:
        # Convert the JSON string to a list
        target.challanges = json.loads(target.challanges)

    if target.questions:
        # Convert the JSON string to a list
        target.questions = json.loads(target.questions)

# Event listener for after_create
@event.listens_for(ModelAdministrationAuthenticationProfile.__table__, 'after_create')  # type: ignore
def aftercreate_model_administration_authentication_profile(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelAdministrationAuthenticationProfile triggered")

    try:

        dbprovider.add(ModelAdministrationAuthenticationProfile(
            name='Default Authentication',
            system_defined=True,
            description='This is the default user login profile with multifactor authentication disabled.',
        ))

        dbprovider.add(ModelAdministrationAuthenticationProfile(
            name='OAuth MFA Authentication',
            system_defined=True,
            challanges='["oauth"]',
            description='This is the default user login profile with multifactor authentication enabled using OAuth.',
        ))

        dbprovider.add(ModelAdministrationAuthenticationProfile(
            name='Security Question Authentication',
            system_defined=True,
            challanges='["question"]',
            description='This is the default user login profile with multifactor authentication enabled using security questions.',
        ))

    except Exception as e:
        service_logger().error(f"after_create: ModelAdministrationAuthenticationProfile error: {e}")




class ModelAdministrationAuthenticationSecQuestion(dbBase):
    __tablename__ = 'administration_authentication_secquestion'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    public_id = Column(String, nullable=False, unique=True)
    question = Column(String, nullable=False, unique=True)
    answer = Column(String, nullable=False, unique=False)
    case_sensitive = Column(Boolean, nullable=True, default=False)
    crypted = Column(Boolean, nullable=True, default=False)
    author = Column(String, nullable=True)

    def __init__(self, **kwargs):
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")

        super().__init__(**kwargs)

    def __repr__(self):
        return f'<Table/Administration/AuthenticationSecQuestion -- question: {self.question}>'

    @staticmethod
    def text_to_crypt(value):
        try:
            if isinstance(value, str):  # Ensure value is a string before encrypting
                return service_cryptography().text_to_crypt(value)  # Use encryption, not hashing
            else:
                raise TypeError("The value to be encrypted must be a string.")
        
        except Exception as e:
            service_logger().warning(f"Error model text_to_crypt: {e}")
            return value  # Return None or handle error as needed

    @staticmethod
    def crypt_to_text(value):
        try:
            return service_cryptography().crypt_to_text(value)
        
        except Exception as e:
            service_logger().warning(f"Error model crypt_to_text: {e}")
            return value  # Return None or handle error as needed
    
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
    

    @staticmethod
    def generate_public_id():
        global first_public_id_authentication_secquestion
        new_public_id = str(first_public_id_authentication_secquestion+1)

        try:
            # Check if the partition table exists
            inspector = inspect(dbprovider.bind)

            # Check if the partition table exists
            if inspector.has_table(ModelAdministrationAuthenticationSecQuestion.__tablename__):

                last_object = dbprovider.query(ModelAdministrationAuthenticationSecQuestion) \
                    .order_by(ModelAdministrationAuthenticationSecQuestion.public_id.desc()) \
                    .first()
                
                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)

            else:
                # Table does not exist, create it or handle the error accordingly
                service_logger().warning("Table administration_authentication_secquestion does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        first_public_id_authentication_secquestion += 1  # Increment the first_public_id_authentication_secquestion
        
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
            instance = dbprovider.query(ModelAdministrationAuthenticationSecQuestion).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    def remove_object(self):
        """Remove object from the database."""
        self._delete()

@event.listens_for(ModelAdministrationAuthenticationSecQuestion.__mapper__, 'before_insert')
def value_to_unique(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationAuthenticationSecQuestion before_insert triggered")

    # Check for uniqueness of the lowercase team name
    existing_question = dbprovider.query(ModelAdministrationAuthenticationSecQuestion).filter(
        func.lower(ModelAdministrationAuthenticationSecQuestion.question) == target.question.lower()
    ).first()

    if existing_question:
        raise ValueError("Question must be unique.")

    if target.crypted:
        setattr(target, 'answer', target.text_to_crypt(target.answer))

    return target

@event.listens_for(ModelAdministrationAuthenticationSecQuestion.__mapper__, 'before_update')
def value_to_crypt(mapper, connection, target):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationAuthenticationSecQuestion before_update triggered")

    if target.crypted:
        setattr(target, 'answer', target.text_to_crypt(target.answer))
    
    return target

@event.listens_for(ModelAdministrationAuthenticationSecQuestion, 'load')
def value_to_text(target, context):
    if class_configuration().return_app_debug_mode():
        service_logger_debug().debug("ModelAdministrationAuthenticationSecQuestion query triggered")

    if target.crypted:
        target.answer = target.crypt_to_text(target.answer)

# Event listener for after_create
@event.listens_for(ModelAdministrationAuthenticationSecQuestion.__table__, 'after_create')  # type: ignore
def aftercreate_model_administration_authentication_secquestion(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelAdministrationAuthenticationSecQuestion triggered")

    try:

        dbprovider.add(ModelAdministrationAuthenticationSecQuestion(
            question='What programming language did you learn first?',
            answer='Python'
        ))

        dbprovider.add(ModelAdministrationAuthenticationSecQuestion(
            question='Please enter secure passcode',
            answer='SOBE',
            case_sensitive=True,
        ))

    except Exception as e:
        service_logger().error(f"after_create: ModelAdministrationAuthenticationSecQuestion error: {e}")
