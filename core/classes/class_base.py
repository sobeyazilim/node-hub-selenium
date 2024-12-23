from fastapi import  Request, HTTPException
from time import  localtime, strftime
from datetime import datetime, timedelta
import jwt
import secrets
import string
import re

# models that imported for table trigger after create events
# models that imported for table trigger after create events
from core.models.SQLAlchemy.administration.ModelAdministrationUserManagementUser import ModelAdministrationUserManagementUser
from core.models.SQLAlchemy.administration.ModelAdministrationUserManagementDirectoryConnector import ModelAdministrationUserManagementDirectoryConnector
from core.models.SQLAlchemy.administration.ModelAdministrationAuthentication import ModelAdministrationAuthenticationProfile, ModelAdministrationAuthenticationSecQuestion
from core.models.SQLAlchemy.administration.ModelAdministrationUserManagementTeam import ModelAdministrationUserManagementTeam
from core.models.SQLAlchemy.sensor.ModelSensorIncidents import ModelSensorIncidents
from core.models.SQLAlchemy.ModelHistory import ModelHistoryLogin
from core.models.SQLAlchemy.ModelNotifications import ModelNotificationAlert

from core.models.SQLAlchemy.cyberpot.ModelCyberpotDecoys import ModelCyberPotDecoys
from core.models.SQLAlchemy.cyberpot.ModelCyberpotDeployments import ModelCyberPotDeployments
from core.models.SQLAlchemy.cyberpot.ModelCyberpotResources import ModelCyberPotResources

from core.models.SQLAlchemy.configuration.ModelConfiguration import ModelConfiguration
from core.models.SQLAlchemy.configuration.ModelConfigurationSegment import ModelConfigurationSegment

# class
from core.classes.class_configuration import class_configuration
from core.classes.class_administration import class_administration

# services
from core.services.serviceLogger import service_logger, service_logger_debug

class class_base:
    def __init__(self):
        self.classbase = "class/base"
        self.app_jwt_key = class_configuration().return_app_jwt_key()
        self.app_jwt_private_key = class_configuration().return_app_jwt_private_key()
        self.app_jwt_public_key = class_configuration().return_app_jwt_public_key()
        self.app_jwt_symetric_algorithm = class_configuration().return_app_jwt_symetric_algorithm()
        self.app_jwt_asymetric_algorithm = class_configuration().return_app_jwt_asymetric_algorithm()
        self.app_login_timeout = class_configuration().return_app_login_timeout()

    def generate_auth_token(self, public_id: str):
        try:
            payload = {"public_id": public_id, "exp": datetime.now() + timedelta(minutes=self.app_login_timeout)}
            
            # Generate the token
            token = jwt.encode(payload, self.app_jwt_private_key, algorithm=self.app_jwt_asymetric_algorithm)
            
        except Exception as error:
            service_logger().error(f'generate_auth_token error: {error}')
            return None
        
        return token
    
    def verify_auth_token(self, request: Request, token: str = None):
        if token is None:
            return False
        
        try:

            payload = jwt.decode(token, self.app_jwt_public_key, algorithms=[self.app_jwt_asymetric_algorithm])
            public_id = payload.get("public_id")
            
            if class_administration().return_public_id_exist(public_id):
                return True

            return False
        
        except jwt.ExpiredSignatureError:
            return False
        
        except jwt.InvalidTokenError:
            return False
        
        except Exception as error:
            service_logger().error(f'verify_auth_token error: {error}')
            return False

    def return_auth_token_public_id(self, token: str = None):
        if token is None:
            return None
        try:

            payload = jwt.decode(token, self.app_jwt_public_key, algorithms=[self.app_jwt_asymetric_algorithm])
            public_id = payload.get("public_id")

            return public_id
        
        except jwt.ExpiredSignatureError:
            return None
        
        except jwt.InvalidTokenError:
            return None

        except Exception as error:
            service_logger().error(f'return_auth_token_public_id error: {error}')
            return False
        
    def token_dependency_check(self, request: Request):
        # List of paths to exclude from token check
        excluded_paths = ["/login", "/auth", "/socket", "/static"]
        
        # Bypass token check for the root path ("/") or excluded paths
        if any(request.url.path.startswith(path) for path in excluded_paths):
            return
        
        # Retrieve the token from the cookie
        token = request.cookies.get(class_configuration().return_app_jwt_token_label())
        
        # Implement your token verification logic here
        if not token or not class_base().verify_auth_token(request, token):
            # Redirect to login page if token is invalid or missing
            request.session["warning_message"] = "You must log in to access"
            raise HTTPException(status_code=302, detail="Redirect to /login", headers={"Location": "/login"})

    def generate_brain_token(self, length=48):
        """Generate a secure random key for sensor authentication using only letters and digits."""
        # Define the characters to use in the key (uppercase, lowercase, and digits)
        characters = string.ascii_letters + string.digits
        # Generate a random key
        key = ''.join(secrets.choice(characters) for _ in range(length))
        return key

    def is_weak_password(password):
        # Extended list of common weak passwords
        common_passwords = [
            "password", "123456", "123456789", "12345678", "12345", "1234567", 
            "123123", "111111", "987654321", "qwerty", "letmein", "welcome", 
            "admin", "monkey", "abc123", "1q2w3e4r", "passw0rd", "password1",
            "zaq1zaq1", "password123", "654321", "qwertyuiop", "michael", 
            "superman", "iloveyou", "sunshine", "princess", "football", 
            "baseball", "dragon", "shadow", "whatever", "trustno1", "hello", 
            "freedom", "access", "mustang", "charlie", "starwars"
        ]

        # Check if the password matches any common weak passwords (with or without special characters)
        for common_pass in common_passwords:
            if password.lower().startswith(common_pass) and re.match(rf"^{common_pass}\W*$", password.lower()):
                return True

        # Check if the password contains a 4-digit year between 1900 and 2099
        if re.search(r'(19\d{2}|20\d{2})', password):
            return True

        # Check for 3 consecutive digits (ascending or descending)
        if re.search(r'(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)', password):
            return True

        # Check for 3 consecutive characters (ascending or descending)
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        for i in range(len(alphabet) - 2):
            if alphabet[i:i+3] in password.lower() or alphabet[i+2:i-1:-1] in password.lower():
                return True

        # Check for repeated characters (e.g., 'aaaaaa' or '111111')
        if re.fullmatch(r'(.)\1{3,}', password):
            return True

        # Check for repeating patterns (e.g., 'ababab', '121212')
        if re.fullmatch(r'(.{1,2})\1{2,}', password):
            return True

        return False