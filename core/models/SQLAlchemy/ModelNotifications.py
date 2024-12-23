# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, DateTime, Date, event
from sqlalchemy.orm import Session
from fastapi import HTTPException
from typing import Any
from datetime import datetime

# providers
from core.providers.dbprovider import dbBase, dbprovider

# services
from core.services.serviceLogger import service_logger, service_logger_debug

# notification>alert models
class ModelNotificationAlert(dbBase):
    """notification/alert model."""
    __tablename__ = 'notification_alert'
    __table_args__ = { 'quote': False, 'extend_existing': True }
    id = Column(
        Integer,
        primary_key=True
    )
    level = Column(
        String(100),
        nullable = False,
        unique = False
    )
    event = Column(
        String(100),
        nullable = False,
        unique = False
    )
    login_name = Column(
        String,
        nullable = True,
        unique = False
    )
    source_ip_address = Column(
        String,
        nullable = False,
        unique = False
    )
    source_device = Column(
        String,
        nullable = True,
        unique = False
    )
    source_browser = Column(
        String,
        nullable = True,
        unique = False
    )
    source_os = Column(
        String,
        nullable = True,
        unique = False
    )
    referer = Column(
        String,
        nullable = True,
        unique = False
    )
    message = Column(
        String,
        nullable = True,
        unique = False
    )
    created_on = Column(
        DateTime,
        nullable = False,
        unique = False
    )
    seen = Column(
        Boolean,
        nullable = True,
        unique = False,
        default = False
    )
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __repr__(self):
        return '<Table/Notification/Alert -- event: {}>'.format(self.event)

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
            instance = dbprovider.query(ModelNotificationAlert).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    def patch_object_seen(self, status):
        """ patch seen """
        self.seen = status
        self._update()

    def remove_object(self):
        """Remove object from the database."""
        self._delete()

class model_notification_alert_insert:
    @staticmethod
    def init(level: str, event: str, pydantic_data: Any, message: str) -> None:
        """Insert a new notification alert into the database"""
        try:
            data_element = ModelNotificationAlert(
                level=level,
                event=event,
                login_name=pydantic_data.login_name,
                source_ip_address=pydantic_data.source_ip_address,
                source_device=pydantic_data.source_device,
                source_browser=pydantic_data.source_browser,
                source_os=pydantic_data.source_os,
                referer=pydantic_data.referer,
                message=message,
                created_on=datetime.now()
            )

            # Insert into the database and commit
            dbprovider.add(data_element)
            dbprovider.commit()
        
        except Exception as e:
            dbprovider.rollback()
            raise HTTPException(status_code=500, detail="An error occurred while inserting data") from e