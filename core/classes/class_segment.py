# primary libraries
from time import localtime, strftime
from fastapi import HTTPException
from datetime import datetime
from sqlalchemy.exc import DBAPIError
from typing import Optional
import json

# models
from core.models.SQLAlchemy.configuration.ModelConfigurationSegment import ModelConfigurationSegment
from core.models.SQLAlchemy.ModelHistory import model_history_login_insert
from core.models.SQLAlchemy.ModelNotifications import model_notification_alert_insert

# class
from core.classes.class_configuration import class_configuration

# providers
from core.providers.dbprovider import dbprovider

# services
from core.services.serviceLogger import service_logger, service_logger_debug
from core.services.serviceLdap import service_ldap

class class_segment:
    def __init__(self):
        self.classbase = "class/segment"

    def return_configuration_segments(self):
        try:
            segments = dbprovider.query(ModelConfigurationSegment).order_by(ModelConfigurationSegment.segment_name.asc()).all()
            return segments
        except DBAPIError as e:
            service_logger().error(f"SQLAlchemy error retrieving segments: {e}")
            return []

    def return_segment_by_public_id(self, public_id: str) -> Optional[ModelConfigurationSegment]:
        try:
            # Find desired segment object
            segment = dbprovider.query(ModelConfigurationSegment).filter(ModelConfigurationSegment.public_id == public_id).one_or_none()
            
            # convert item to dict
            if segment:
                return segment.as_dict()
            else:
                service_logger().warning(f"No segment found with public_id: {public_id}")

        except DBAPIError as e:
            service_logger().error(f"Error retrieving segment object with public_id {public_id}: {e}")
        
        return None

    def is_editable(self, public_id: str) -> bool:
        try:
            # find desired segment object
            segment = dbprovider.query(ModelConfigurationSegment).filter(ModelConfigurationSegment.public_id == public_id).first()
            
            if segment and not segment.system_defined:
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error retrieving object: {e}")
        return False
    
    def has_reference_with_segment(self, public_id: str) -> bool:
        return False

    def delete_segment_by_public_id(self, public_id: str) -> bool:
        try:
            # check whether segment has any reference
            if self.has_reference_with_segment(public_id=public_id):
                return False
            
            # find desired segment object
            segment = dbprovider.query(ModelConfigurationSegment).filter(ModelConfigurationSegment.public_id == public_id).first()
            
            if segment and not segment.system_defined:
                segment.remove_object()
                return True
            
        except DBAPIError as e:
            service_logger().error(f"Error remove object: {e}")
        return False
    
    def update_segment(self, pydantic_data, auto_create: bool = True) -> bool:
        try:
            # check item
            model_segment = dbprovider.query(ModelConfigurationSegment).filter_by(segment_name=pydantic_data.segment_name).first()
            
            if model_segment:
                model_segment.segment_hosts = pydantic_data.segment_hosts
            else:
                if auto_create:
                    # create new record
                    model_segment = ModelConfigurationSegment(
                        segment_name=pydantic_data.segment_name,
                        segment_hosts=pydantic_data.segment_hosts
                    )
                    dbprovider.add(model_segment)

            dbprovider.commit()

            return True
    
        except Exception as error:
            service_logger().critical(f"*** Segment update error: {error} ")
            dbprovider.rollback()
            
            return False