# primary libraries
from decimal import Decimal
from time import localtime, strftime
from fastapi import HTTPException
from datetime import datetime
from sqlalchemy.exc import DBAPIError
import json

# models
from core.models.SQLAlchemy.cyberpot.ModelCyberpotDecoys import ModelCyberPotDecoys
from core.models.SQLAlchemy.cyberpot.ModelCyberpotDeployments import ModelCyberPotDeployments
from core.models.SQLAlchemy.cyberpot.ModelCyberpotResources import ModelCyberPotResources

# class
from core.classes.class_configuration import class_configuration

# providers
from core.providers.dbprovider import dbprovider

# services
from core.services.serviceLogger import service_logger, service_logger_debug
from core.services.serviceLdap import service_ldap

class class_cyberpot:
    def __init__(self):
        self.classbase = "class/cyberpot"

    def return_cyberpot_decoys(self):
        try:
            decoys = dbprovider.query(ModelCyberPotDecoys).filter(ModelCyberPotDecoys.tool != True ).order_by(ModelCyberPotDecoys.name.asc()).all()
            return decoys
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving cyberpot decoys: {e}")
            return []
        
    def return_cyberpot_deployments(self):
        try:
            decoys = dbprovider.query(ModelCyberPotDeployments).order_by(ModelCyberPotDeployments.name.asc()).all()
            return decoys
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving cyberpot deployment: {e}")
            return None

    def return_cyberpot_resources(self):
        try:
            results = dbprovider.query(ModelCyberPotResources).all()
            # return as a dict
            return {d.attribute: float(d.value) if isinstance(d.value, Decimal) else int(d.value) for d in results}
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving cyberpot resources: {e}")
            return None
        
    def return_cybertpot_decoy_by_public_id(self, public_id: str):
        try:
            decoy = dbprovider.query(ModelCyberPotDecoys).filter(ModelCyberPotDecoys.public_id == public_id).first()
            if decoy:
                return decoy.as_dict()
            return False
        except DBAPIError as e:
            service_logger().error(f"Error retrieving cyberpot decoy by public ID: {e}")
            return None
        
    def return_cybertpot_deployment_by_public_id(self, public_id: str):
        try:
            decoy = dbprovider.query(ModelCyberPotDeployments).filter(ModelCyberPotDeployments.public_id == public_id).first()
            if decoy:
                return decoy.as_dict()
            return False
        except DBAPIError as e:
            service_logger().error(f"Error retrieving cyberpot deployment by public ID: {e}")
            return None

    def delete_cyberpot_deployment_by_public_id(self, public_id:str) -> bool:
        try:
            instance = dbprovider.query(ModelCyberPotDeployments).filter(ModelCyberPotDeployments.public_id == public_id).first()
            dbprovider.delete(instance)
            dbprovider.commit()
            return True
        except Exception as error:
            service_logger().error(f"Error remove cyberpot deployment object: {error}")
            dbprovider.rollback()
            return False
        
    def update_cyberpot_deployment(self, pydantic_data, auto_create: bool = True) -> bool:
        try:
            if class_configuration().return_app_debug_mode():
                service_logger_debug().debug(pydantic_data)
            # check data
            model_deployment = dbprovider.query(ModelCyberPotDeployments).filter_by(public_id=pydantic_data.public_id).first()
            # edit operation  
            if model_deployment:
                model_deployment.username = pydantic_data.username
                model_deployment.password = pydantic_data.password
                model_deployment.api_token = pydantic_data.api_token
                model_deployment.permissions = pydantic_data.permissions
                model_deployment.enabled = pydantic_data.enabled
            else:
                # create operation
                if auto_create:
                    model_deployment = ModelCyberPotDeployments(
                        username = pydantic_data.username,
                        password = pydantic_data.password,
                        api_token = pydantic_data.api_token,
                        permissions = pydantic_data.permissions,
                        user_type = pydantic_data.user_type,
                        enabled = pydantic_data.enabled,
                    )
                    dbprovider.add(model_deployment)
                    
            dbprovider.commit()
            return True
                
        except Exception as error:
            service_logger().critical(f"*** Cyberpot deployment update error: {error} ")
            dbprovider.rollback()
            return False
        
    def update_cyberpot_resource(self, pydantic_data) -> bool:
        try:
            if class_configuration().return_app_debug_mode():
                service_logger_debug().debug(pydantic_data)
                
            print('update_cyberpot_resource pydantic_data: ', pydantic_data)
            # iterate over the Pydantic data and update ModelCyberPotResources instances
            for key, value in pydantic_data.dict().items():
                print(f'key: {key} - value: {value}')
                # check data and get data by attribute
                model_resource = dbprovider.query(ModelCyberPotResources).filter_by(attribute=key).first()
                print('model_resource', model_resource)
                # if exists update it
                if model_resource:
                    model_resource.value = value

            dbprovider.commit()
            return True
                
        except Exception as error:
            service_logger().critical(f"*** Cyberpot deployment update error: {error} ")
            dbprovider.rollback()
            return False