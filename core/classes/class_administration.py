# primary libraries
from sqlalchemy.exc import DBAPIError
from typing import Optional

# models                                   
from core.models.SQLAlchemy.administration.ModelAdministrationUserManagementUser import ModelAdministrationUserManagementUser
from core.models.SQLAlchemy.ModelHistory import model_history_login_insert, ModelHistoryLogin
from core.models.Pydantic.internal import pydantic_request_login_auth

# providers
from core.providers.dbprovider import dbprovider

# services
from core.services.serviceLogger import service_logger

class class_administration:
    def __init__(self):
        self.classbase = "class/administration/usermanagement"

    def return_administration_usermanagement_users_all(self):
        try:
            users = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.login_name != 'master').order_by(ModelAdministrationUserManagementUser.login_name.asc()).all()
            return users
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving users: {e}")
            return []
    
    def return_administration_usermanagement_user_by_public_id(self, public_id: str) -> Optional[ModelAdministrationUserManagementUser]:
        try:
            # Find desired object
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).one_or_none()
            
            # convert item to dict
            if user:
                return user.as_dict()
            else:
                service_logger().warning(f"No user found with public_id: {public_id}")

        except DBAPIError as e:
            service_logger().error(f"Error retrieving user object with public_id {public_id}: {e}")
        
        return None

    def return_public_id_exist(self, public_id: str):
        return bool(dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first())

    def return_login_name_by_public_id(self, public_id: str):
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            if user:
                login_name = user.login_name
                if login_name:
                    return login_name
            return None
        
        except DBAPIError as e:
            service_logger().error(f"Error retrieving user by public ID: {e}")
            return None
    
    def return_public_id_by_login_name(self, login_name: str):
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser)\
                .filter(ModelAdministrationUserManagementUser.login_name == login_name)\
                    .first()
            if user:
                public_id = user.public_id
                if public_id:
                    return public_id
            return None
        except DBAPIError as e:
            service_logger().error(f"Error retrieving user by login name: {e}")
            return None
    
    def verify_old_password_by_public_id(self, public_id: str, password: str) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            if user and password and user.verify_object_password(plain_password=password):
                return True
        except DBAPIError as e:
            service_logger().error(f"Error verifying old password: {e}")
        return False

    def verify_can_change_password(self, public_id: str) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            if user and not user.cannot_change_password:
                return True
        except DBAPIError as e:
            service_logger().error(f"Error verifying can not change password: {e}")
        return False
    
    def reset_password_by_public_id(self, public_id: str, password: str) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            if user and password:
                user.patch_object_password(password=password)
                return True
        except DBAPIError as e:
            service_logger().error(f"Error resetting password: {e}")
        return False

    def reset_counter_lock_by_public_id(self, public_id: str, status: bool) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            if user:
                user.patch_object_counter_lock(status=status)
                return True
        except DBAPIError as e:
            service_logger().error(f"Error resetting counter lock: {e}")
        return False   

    def reset_authentication_oauth_secret_by_public_id(self, public_id: str) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            if user:
                user.reset_object_authentication_oauth_secret()
                return True
        except DBAPIError as e:
            service_logger().error(f"Error resetting oauth secret: {e}")
        return False
    
    def delete_user(self, public_id: str) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            
            if user and not user.system_defined:
                user.remove_object()
                return True
        except DBAPIError as e:
            service_logger().error(f"Error remove object: {e}")
        return False
    
    def return_user_type_by_public_id(self, public_id: str) -> str:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            if user.user_type:
                return user.user_type
        except DBAPIError as e:
            service_logger().error(f"Error retrieving user type: {e}")
        return None

    def return_user_role_by_public_id(self, public_id: str) -> str:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            if user.role:
                return user.role
        except DBAPIError as e:
            service_logger().error(f"Error retrieving user role: {e}")
        
        return 'readonly'

    def update_administration_usermanagement_user(self, pydantic_data, auto_create: bool = True) -> bool:
        try:
            model_user = None
            # Check for existing user
            if pydantic_data.public_id:
                model_user = dbprovider.query(ModelAdministrationUserManagementUser).filter_by(public_id=pydantic_data.public_id).first()

            # Create a dictionary for field updates
            update_fields = {
                'login_name': pydantic_data.login_name,
                'display_name': pydantic_data.display_name,
                'description': pydantic_data.description,
                'user_type': pydantic_data.user_type,
                'directory_source': pydantic_data.directory_source,
                'role': pydantic_data.role,
                'team': pydantic_data.team,
                'email': pydantic_data.email,
                'phone': pydantic_data.phone,
                'authentication_profile': pydantic_data.authentication_profile,
                'cannot_change_password': pydantic_data.cannot_change_password,
                'change_password_at_next_login': pydantic_data.change_password_at_next_login,
                'password_never_expires': pydantic_data.password_never_expires,
                'suspend_lock': pydantic_data.suspend_lock,
                'suspend_lock_until_date': pydantic_data.suspend_lock_until_date,
                'automated_account_expiry': pydantic_data.automated_account_expiry,
                'automated_account_expiry_date': pydantic_data.automated_account_expiry_date,
                'time_based_access_control': pydantic_data.time_based_access_control,
                'time_based_access_control_timezone': pydantic_data.time_based_access_control_timezone,
                'time_based_access_control_start': pydantic_data.time_based_access_control_start,
                'time_based_access_control_end': pydantic_data.time_based_access_control_end,
                'time_based_access_control_days': pydantic_data.time_based_access_control_days,
                'trusted_host_access_control': pydantic_data.trusted_host_access_control,
                'trusted_hosts': pydantic_data.trusted_hosts,
                'enabled': pydantic_data.enabled
            }

            updated_password = None

            if pydantic_data.user_type == 'local':
                if pydantic_data.new_password:
                    updated_password = pydantic_data.new_password

            if pydantic_data.user_type == 'remoterevert':
                if pydantic_data.backup_password:
                    updated_password = pydantic_data.backup_password

            if model_user:
                # Update existing user fields
                for field, value in update_fields.items():
                    if value is not None:  # Update only if value is provided
                        setattr(model_user, field, value)

                if updated_password:
                    model_user.password = updated_password


            elif auto_create:

                # Create new user instance
                model_user = ModelAdministrationUserManagementUser (
                    password=updated_password if updated_password else None,
                    **{k: v for k, v in update_fields.items() if v is not None}  # Unpack only provided fields
                )

                dbprovider.add(model_user)

            dbprovider.commit()
            return True
        
        except Exception as error:
            service_logger().critical(f"*** Usermanagement user update/create error: {error} ")
            dbprovider.rollback()
            return False
        
    def authenticate_user(self, login_name: str, password: str, source_ip_address: str) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(
                ModelAdministrationUserManagementUser.login_name == login_name
            ).first()

            pydantic_data = pydantic_request_login_auth(
                login_name=login_name,
                password=password,
                source_ip_address=source_ip_address
            )
            
            if not user.verify_user_able_to_login(source_ip=source_ip_address):
                reason = user.why_not_able_to_login(source_ip=source_ip_address)
                service_logger().critical(
                    f"*** Unable to authenticate user | event=login | login_name={login_name} | "
                    f"source_ip_address={source_ip_address} | reason={reason}"
                )
                return False
            
            validation_status = False
            
            if user.verify_object_password(plain_password=password):
                validation_status = True
                service_logger().info(
                    f"*** Successful local authentication | event=login | login_name={login_name} | "
                    f"source_ip_address={source_ip_address} | reason=null"
                )
            else:
                service_logger().warning(
                    f"*** Failed local authentication | event=login | login_name={login_name} | "
                    f"source_ip_address={source_ip_address} | reason=Password incorrect"
                )

            if validation_status:
                model_history_login_insert.init(
                    pydantic_data=pydantic_data, stat="successful"
                )

                # reset failed login counter after successful login
                user.reset_object_counter_lock()

                # update last logins
                user.patch_object_last_login_datetime()
                user.patch_object_last_login_ipaddress(source_ip_address)

                return True
            
            else:
                # update failed login counter
                user.countup_object_counter()

                # update counter lock state if it bigger than allowed try
                user.check_object_counter_lock()

                model_history_login_insert.init(
                    pydantic_data=pydantic_data, stat="failed"
                )
                return False
        
        except DBAPIError as e:
            service_logger().error(f"Error authenticating user: {e}")
            return False

    def return_history_logins(self):
        try:
            history_logins = dbprovider.query(ModelHistoryLogin).order_by(ModelHistoryLogin.created_on.desc()).all()
            return history_logins
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving login history: {e}")
            return []
        