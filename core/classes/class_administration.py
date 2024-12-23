# primary libraries
from time import localtime, strftime
from fastapi import HTTPException
from datetime import datetime
from sqlalchemy import and_, any_
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm.attributes import flag_modified
from typing import Optional
import json

# models                                   
from core.models.SQLAlchemy.administration.ModelAdministrationUserManagementUser import ModelAdministrationUserManagementUser
from core.models.SQLAlchemy.administration.ModelAdministrationUserManagementTeam import ModelAdministrationUserManagementTeam
from core.models.SQLAlchemy.administration.ModelAdministrationUserManagementDirectoryConnector import ModelAdministrationUserManagementDirectoryConnector
from core.models.SQLAlchemy.administration.ModelAdministrationAuthentication import ModelAdministrationAuthenticationProfile, ModelAdministrationAuthenticationSecQuestion
from core.models.SQLAlchemy.ModelHistory import model_history_login_insert, ModelHistoryLogin
from core.models.SQLAlchemy.ModelNotifications import model_notification_alert_insert, ModelNotificationAlert
from core.models.Pydantic.internal import pydantic_request_login_auth

# class
from core.classes.class_configuration import class_configuration

# providers
from core.providers.dbprovider import dbprovider

# services
from core.services.serviceLogger import service_logger, service_logger_debug
from core.services.serviceLdap import service_ldap

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

    def return_administration_authentication_profiles_all(self):
        try:
            authentication_profiles = dbprovider.query(ModelAdministrationAuthenticationProfile).order_by(ModelAdministrationAuthenticationProfile.name.asc()).all()
            return authentication_profiles
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving authentication profiles: {e}")
            return []
        
    def return_administration_authentication_secquestions_all(self):
        try:
            authentication_secquestions = dbprovider.query(ModelAdministrationAuthenticationSecQuestion).order_by(ModelAdministrationAuthenticationSecQuestion.question.asc()).all()
            return authentication_secquestions
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving authentication secquestions: {e}")
            return []
        
    def return_administration_usermanagement_users_by_team(self, team):
        try:
            users = dbprovider.query(ModelAdministrationUserManagementUser).filter(
                and_(
                    ModelAdministrationUserManagementUser.login_name != 'master',
                    ModelAdministrationUserManagementUser.role != 'superadmin',
                    ModelAdministrationUserManagementUser.team == team
                )
            ).order_by(ModelAdministrationUserManagementUser.login_name.asc()).all()

            return users
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving users: {e}")
            return []

    def return_administration_usermanagement_users_managable_by_public_id(self, public_id: str) -> Optional[ModelAdministrationUserManagementUser]:
        try:

            logined_user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).one_or_none()
            
            match logined_user.role:
                case 'superadmin':
                    return self.return_administration_usermanagement_users_all()
                case 'teamadmin':
                    return self.return_administration_usermanagement_users_by_team(logined_user.team)
                case 'readonly':
                    return logined_user

        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving users: {e}")
            return []
        
    def return_administration_usermanagement_users_in_same_team_by_public_id(self, public_id: str) -> Optional[ModelAdministrationUserManagementUser]:
        try:
            logined_user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).one_or_none()

            match logined_user.role:
                case 'superadmin':
                    return self.return_administration_usermanagement_users_all()   
                case _:
                    return self.return_administration_usermanagement_users_by_team(logined_user.team)
                
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving users: {e}")
            return []
        
    def is_editable_user(self, public_id: str) -> bool:
        try:
            # find desired user object
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()

            if user:
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error retrieving object: {e}")
        return False

    def is_editable_team(self, public_id: str) -> bool:
        try:
            # find desired team object
            team = dbprovider.query(ModelAdministrationUserManagementTeam).filter(ModelAdministrationUserManagementTeam.public_id == public_id).first()

            if team:
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error retrieving object: {e}")
        return False
    
    def is_editable_directory(self, public_id: str) -> bool:
        try:
            # find desired directory object
            directory = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector).filter(ModelAdministrationUserManagementDirectoryConnector.public_id == public_id).first()

            if directory:
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error retrieving directory object: {e}")
        return False

    def is_editable_authentication_profile(self, public_id: str) -> bool:
        try:
            # find desired profile object
            profile = dbprovider.query(ModelAdministrationAuthenticationProfile).filter(ModelAdministrationAuthenticationProfile.public_id == public_id).first()

            if profile:
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error retrieving profile object: {e}")
        return False
    
    def is_editable_authentication_secquestion(self, public_id: str, login_id: str) -> bool:
        try:
            # find desired secquestion object
            secquestion = dbprovider.query(ModelAdministrationAuthenticationSecQuestion).filter(ModelAdministrationAuthenticationSecQuestion.public_id == public_id).first()

            if secquestion:
                if secquestion.crypted and secquestion.author and secquestion.author != login_id:
                    service_logger().error(f"Can not edit authentication question. User is not author.")
                    return False
                
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error retrieving secquestion object: {e}")
        return False
    
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

    def return_administration_usermanagement_team_by_public_id(self, public_id: str) -> Optional[ModelAdministrationUserManagementTeam]:
        try:
            # Find desired object
            team = dbprovider.query(ModelAdministrationUserManagementTeam).filter(ModelAdministrationUserManagementTeam.public_id == public_id).one_or_none()
            
            # convert item to dict
            if team:
                return team.as_dict()
            else:
                service_logger().warning(f"No team found with public_id: {public_id}")

        except DBAPIError as e:
            service_logger().error(f"Error retrieving team object with public_id {public_id}: {e}")
        
        return None
    
    def return_administration_usermanagement_directory_by_public_id(self, public_id: str) -> Optional[ModelAdministrationUserManagementDirectoryConnector]:
        try:
            # Find desired object
            directory = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector).filter(ModelAdministrationUserManagementDirectoryConnector.public_id == public_id).one_or_none()
            
            # convert item to dict
            if directory:
                return directory.as_dict()
            else:
                service_logger().warning(f"No directory found with public_id: {public_id}")

        except DBAPIError as e:
            service_logger().error(f"Error retrieving directory object with public_id {public_id}: {e}")
        
        return None

    def return_administration_authentication_profile_by_public_id(self, public_id: str) -> Optional[ModelAdministrationAuthenticationProfile]:
        try:
            # Find desired object
            profile = dbprovider.query(ModelAdministrationAuthenticationProfile).filter(ModelAdministrationAuthenticationProfile.public_id == public_id).one_or_none()
                        
            # convert item to dict
            if profile:
                return profile.as_dict()
            else:
                service_logger().warning(f"No auth profile found with public_id: {public_id}")

        except DBAPIError as e:
            service_logger().error(f"Error retrieving auth profile object with public_id {public_id}: {e}")
        
        return None

    def return_administration_authentication_secquestion_by_public_id(self, public_id: str) -> Optional[ModelAdministrationAuthenticationSecQuestion]:
        try:
            # Find desired object
            secquestion = dbprovider.query(ModelAdministrationAuthenticationSecQuestion).filter(ModelAdministrationAuthenticationSecQuestion.public_id == public_id).one_or_none()
                        
            # convert item to dict
            if secquestion:
                return secquestion.as_dict()
            else:
                service_logger().warning(f"No auth secquestion found with public_id: {public_id}")

        except DBAPIError as e:
            service_logger().error(f"Error retrieving auth secquestion object with public_id {public_id}: {e}")
        
        return None
    
    def return_administration_usermanagement_user_team_by_public_id(self, public_id: str) -> Optional[str]:
        try:
            # Find desired object
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).one_or_none()
            
            # Check if user is found and return the team
            if user:
                return user.team
            else:
                service_logger().warning(f"No user found with public_id: {public_id}")
            
        except DBAPIError as e:
            service_logger().error(f"Error retrieving user object with public_id {public_id}: {e}")
        
        return None

    def return_administration_usermanagement_teams(self):
        try:
            teams = dbprovider.query(ModelAdministrationUserManagementTeam).order_by(ModelAdministrationUserManagementTeam.name.asc()).all()
            return teams
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving teams: {e}")
            return []

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
    
    def return_team_by_public_id(self, public_id: str):
        try:
            team = dbprovider.query(ModelAdministrationUserManagementTeam).filter(ModelAdministrationUserManagementTeam.public_id == public_id).one_or_none()
            if team:
                return team
            
        except DBAPIError as e:
            service_logger().error(f"Error retrieving team by public ID: {e}")
            return None

    def return_team_name_by_public_id(self, public_id: str):
        try:
            team = dbprovider.query(ModelAdministrationUserManagementTeam).filter(ModelAdministrationUserManagementTeam.public_id == public_id).first()
            if team:
                team_name = team.name
                if team_name:
                    return team_name
            return None
        
        except DBAPIError as e:
            service_logger().error(f"Error retrieving team by public ID: {e}")
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
     
    def update_user_enabled(self, public_id: str, status: bool) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            
            if user:
                user.patch_object_enabled(status)
                return True
        except DBAPIError as e:
            service_logger().error(f"Error enabled status: {e}")
        return False
    
    def update_user_trusted_host_access_control(self, public_id: str, status: bool) -> bool:
        try:
            user = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.public_id == public_id).first()
            
            if user:
                user.patch_object_trusted_host_access_control(status)
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error trusted host control status: {e}")
        return False
    
    def has_reference_with_directory_connector(self, public_id: str)-> bool:
        try:
            references_count = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.directory_source
                                                                                  == public_id).count()
            if references_count > 0:
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error checking team reference: {e}")
        
        return False 
    
    
    def has_reference_with_team(self, public_id: str) -> bool:
        try:
            references_count = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.team == public_id).count()
        
            if references_count > 0:
                return True
        
        except DBAPIError as e:
            service_logger().error(f"Error checking team reference: {e}")
        
        return False   
    
    def has_reference_with_authentication_profile(self, public_id: str) -> bool:
        try:
            references_count = dbprovider.query(ModelAdministrationUserManagementUser).filter(ModelAdministrationUserManagementUser.authentication_profile == public_id).count()
        
            if references_count > 0:
                return True
        
        except DBAPIError as e:
            service_logger().error(f"Error checking authentication profile reference: {e}")
        
        return False

    def has_reference_with_authentication_secquestion(self, public_id: str) -> bool:
        try:
            references_count = dbprovider.query(ModelAdministrationAuthenticationProfile).filter(
                ModelAdministrationAuthenticationProfile.questions.like(f"%{public_id}%")
            ).count()

            if references_count > 0:
                return True
        
        except DBAPIError as e:
            service_logger().error(f"Error checking authentication secquestion reference: {e}")
        
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
    
    def delete_directory_connector_by_public_id(self, public_id: str) -> bool:
        try:
            directory = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector).filter(ModelAdministrationUserManagementDirectoryConnector.public_id == public_id).first()
            
            if directory and not self.has_reference_with_directory_connector(public_id):
                directory.remove_object()
                return True
        except DBAPIError as e:
            service_logger().error(f"Error remove object: {e}")
        return False
    
    def delete_team(self, public_id: str) -> bool:
        try:
            # check whether team has user member
            if self.has_reference_with_team(public_id=public_id):
                return False
            
            # find desired team object
            team = dbprovider.query(ModelAdministrationUserManagementTeam).filter(ModelAdministrationUserManagementTeam.public_id == public_id).first()
            
            if team and not team.system_defined:
                team.remove_object()
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error remove object: {e}")
        return False
    
    def delete_authentication_profile(self, public_id: str) -> bool:
        try:
            # check any reference exist
            if self.has_reference_with_authentication_profile(public_id=public_id):
                return False
            
            # find desired object
            profile = dbprovider.query(ModelAdministrationAuthenticationProfile).filter(ModelAdministrationAuthenticationProfile.public_id == public_id).first()
            
            if profile and not profile.system_defined:
                profile.remove_object()
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error remove authentication profile object: {e}")
        return False
    
    def delete_authentication_secquestion(self, public_id: str, login_id: str) -> bool:
        try:
            # check any reference exist
            if self.has_reference_with_authentication_secquestion(public_id=public_id):
                return False
            
            # find desired object
            secquestion = dbprovider.query(ModelAdministrationAuthenticationSecQuestion).filter(ModelAdministrationAuthenticationSecQuestion.public_id == public_id).first()
            
            if secquestion:
                # author can delete item
                if secquestion.crypted and secquestion.author and secquestion.author != login_id:
                    return False
                
                secquestion.remove_object()
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error remove authentication secquestion object: {e}")
        return False
    
    def update_directory_connector_enabled_by_public_id(self, public_id: str, status: bool) -> bool:
        try:
            directory_connector = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector).filter(ModelAdministrationUserManagementDirectoryConnector.public_id == public_id).first()
            
            if directory_connector:
                directory_connector.patch_object_enabled(status)
                return True
        except DBAPIError as e:
            service_logger().error(f"Error directory enabled status: {e}")
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
    
    def update_administration_usermanagement_team(self, pydantic_data, auto_create: bool = True) -> bool:
        try:

            model_team = None

            # available field to update
            update_fields = {
                'name': pydantic_data.name,
                'description': pydantic_data.description,
            }

            # Check for existing user
            if pydantic_data.public_id:

                # check item
                model_team = dbprovider.query(ModelAdministrationUserManagementTeam).filter_by(public_id=pydantic_data.public_id).first()
                
            if model_team:
                # Update existing fields
                for field, value in update_fields.items():
                    if value is not None:  # Update only if value is provided
                        setattr(model_team, field, value)

            else:
                if auto_create:
                    # Create new instance
                    model_team = ModelAdministrationUserManagementTeam (
                        **{k: v for k, v in update_fields.items() if v is not None}
                    )
                    dbprovider.add(model_team)

            dbprovider.commit()

            return True
    
        except Exception as error:
            service_logger().critical(f"*** Usermanagement Team update error: {error} ")
            dbprovider.rollback()
            
            return False

    def update_administration_authentication_profile(self, pydantic_data, auto_create: bool = True) -> bool:
        try:

            model_profile = None

            # available field to update
            update_fields = {
                'name': pydantic_data.name,
                'pass_through_duration': pydantic_data.pass_through_duration,
                'challanges': pydantic_data.challanges,
                'questions': pydantic_data.questions,
                'description': pydantic_data.description,
            }

            # Check for existing user
            if pydantic_data.public_id:

                # check item
                model_profile = dbprovider.query(ModelAdministrationAuthenticationProfile).filter_by(public_id=pydantic_data.public_id).first()
                
            if model_profile:
                # Update existing fields
                for field, value in update_fields.items():
                    if value is not None:  # Update only if value is provided
                        setattr(model_profile, field, value)

            else:
                if auto_create:
                    # Create new instance
                    model_profile = ModelAdministrationAuthenticationProfile (
                        **{k: v for k, v in update_fields.items() if v is not None}
                    )
                    dbprovider.add(model_profile)

            dbprovider.commit()

            return True
    
        except Exception as error:
            service_logger().critical(f"*** Authentication Profile update error: {error} ")
            dbprovider.rollback()
            
            return False
    
    def update_administration_authentication_secquestion(self, pydantic_data, auto_create: bool = True) -> bool:
        try:

            model_secquestion = None

            # available field to update
            update_fields = {
                'question': pydantic_data.question,
                'answer': pydantic_data.answer,
                'case_sensitive': pydantic_data.case_sensitive,
                'crypted': pydantic_data.crypted,
            }

            # Check for existing user
            if pydantic_data.public_id:

                # check item
                model_secquestion = dbprovider.query(ModelAdministrationAuthenticationSecQuestion).filter_by(public_id=pydantic_data.public_id).first()
                
            if model_secquestion:
                # Update existing fields
                for field, value in update_fields.items():
                    if value is not None:  # Update only if value is provided
                        setattr(model_secquestion, field, value)
                        # Mark the field as modified to ensure the update occurs
                        flag_modified(model_secquestion, field)
            else:
                if auto_create:
                    # Create new instance
                    model_secquestion = ModelAdministrationAuthenticationSecQuestion (
                        author=pydantic_data.author if pydantic_data.author else None,
                        **{k: v for k, v in update_fields.items() if v is not None}
                    )
                    dbprovider.add(model_secquestion)

            dbprovider.commit()

            return True
    
        except Exception as error:
            service_logger().critical(f"*** Authentication SecQuestion update error: {error} ")
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
                model_notification_alert_insert.init(
                    level="alert", event="login", pydantic_data=pydantic_data, 
                    message=reason
                )
                return False
            
            validation_status = False
            
            match user.user_type:
                case "local":
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
                case "remote":
                    if service_ldap.init(pydantic_data=pydantic_data, directory_source_pid=user.directory_source):
                        validation_status = True

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
        
    def return_directory_connectors(self) -> list:
        """Return all attributes and values as a list of dictionaries, handling JSON values."""
        results = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector).order_by(ModelAdministrationUserManagementDirectoryConnector.name.asc()).all()
        
        # Convert each object in the result list to a dictionary using the as_dict method
        results_as_list = [result.as_dict() for result in results]
        
        return results_as_list
    
    def update_directory_connector(self, pydantic_data, auto_create: bool = True) -> bool:
        
        try:
            model_directory = None
            # Check for existing user
            if pydantic_data.public_id:
                model_directory = dbprovider.query(ModelAdministrationUserManagementDirectoryConnector).filter_by(public_id=pydantic_data.public_id).first()

            # Create a dictionary for field updates
            update_fields = {
                'name': pydantic_data.name,
                'server_ip_or_name': pydantic_data.server_ip_or_name,
                'replica_server_ip_or_name': pydantic_data.replica_server_ip_or_name,
                'server_port': pydantic_data.server_port,
                'base_distinguished_name': pydantic_data.base_distinguished_name,
                'netbios_hostname': pydantic_data.netbios_hostname,
                'common_name_identifier': pydantic_data.common_name_identifier,
                'bind_username': pydantic_data.bind_username,
                'secure_connection': pydantic_data.secure_connection,
                'certificate': pydantic_data.certificate,
                'server_identity_check': pydantic_data.server_identity_check,
                'connect_timeout': pydantic_data.connect_timeout,
                'description': pydantic_data.description,
                'readonly': pydantic_data.readonly,
                'enabled': pydantic_data.enabled
            }


            if model_directory:
                # Update existing user fields
                for field, value in update_fields.items():
                    if value is not None:  # Update only if value is provided
                        setattr(model_directory, field, value)

                if pydantic_data.bind_password:
                    model_directory.bind_password = pydantic_data.bind_password

            elif auto_create:

                # Create new user instance
                model_directory = ModelAdministrationUserManagementDirectoryConnector (
                    bind_password=pydantic_data.bind_password if pydantic_data.bind_password else None,
                    **{k: v for k, v in update_fields.items() if v is not None}  # Unpack only provided fields
                )

                dbprovider.add(model_directory)

            dbprovider.commit()
            return True
        
        except Exception as error:
            service_logger().critical(f"*** Usermanagement ldapserver update/create error: {error} ")
            dbprovider.rollback()
            return False


    def return_history_logins(self):
        try:
            history_logins = dbprovider.query(ModelHistoryLogin).order_by(ModelHistoryLogin.created_on.desc()).all()
            return history_logins
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving login history: {e}")
            return []

    def return_notifications_all(self):
        try:
            notifications_all = dbprovider.query(ModelNotificationAlert).order_by(ModelNotificationAlert.created_on.desc()).all()
            return notifications_all
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving notifications: {e}")
            return []

    def return_notifications_unseen(self):
        try:
            notifications_unseen = dbprovider.query(ModelNotificationAlert).filter(ModelNotificationAlert.seen != True).order_by(ModelNotificationAlert.created_on.desc()).all()
            return notifications_unseen
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving notifications: {e}")
            return []
        
    def patch_notification_seen(self, id: int) -> bool:
        try:
            notification = dbprovider.query(ModelNotificationAlert).filter(ModelNotificationAlert.id == id).one_or_none()
            if notification:
                notification.patch_object_seen(True)
                return True
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving notifications: {e}")
            return False
        
    def patch_notification_seen_all(self) -> bool:
        try:
            notifications_unseen = dbprovider.query(ModelNotificationAlert).filter(ModelNotificationAlert.seen != True).all()
            if notifications_unseen:
                for notification in notifications_unseen:
                    notification.seen = True
                    
                dbprovider.commit()
                return True
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving notifications: {e}")
            return False