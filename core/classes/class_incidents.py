# primary libraries
from time import localtime, strftime
from fastapi import HTTPException
from sqlalchemy import inspect
import jwt
import datetime
import json

# models
from core.models.SQLAlchemy.sensor.ModelSensorIncidents import ModelSensorIncidents
from core.models.Pydantic.internal import pydantic_request_login_auth

# providers
from core.providers.dbprovider import dbprovider

# class
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceLogger import service_logger, service_logger_debug
from core.services.serviceLdap import service_ldap


class class_incidents:
    def __init__(self):
        self.classbase = "class/incidents"

    def return_all_incidents(self):
        incidents = dbprovider.query(ModelSensorIncidents).all()
        return incidents is not None
    
    async def insert_incidents(self, event_batch: list[dict]) -> None:
        try:
            if not class_configuration().return_database_store_incidents():
                service_logger().warning("Storing incidents on database not enabled")
                return
            
            if not isinstance(event_batch, list) or not all(isinstance(item, dict) for item in event_batch):
                service_logger().error("Error: event_batch must be a list of dictionaries")
                return
            
            for event in event_batch:

                inserted_table_name = f"sensor_incidents_{event['ioc_date_created'].replace("-","")}"

                # Check if the partition table exists
                inspector = inspect(dbprovider.bind)

                # Check if the partition table exists
                if not inspector.has_table(inserted_table_name):
                    service_logger().error(f"Error: Partition table '{inserted_table_name}' does not exist")
                    continue  # Skip to the next event

                try:
                    # Create a ModelSensorIncidents object
                    incident_obj = ModelSensorIncidents(**event)

                    # Add or update the object in the session
                    dbprovider.merge(incident_obj)

                    # Commit the transaction if all events were processed successfully
                    dbprovider.commit()

                except Exception as error:
                    # Log the error and skip this event
                    # print(f"Error inserting event: {error}")

                    # Rollback the transaction in case of an error during batch processing
                    dbprovider.rollback()

                    # Optionally, log the error or take other appropriate action
                    continue  # Skip to the next event
            
            # print("All events processed successfully!")

        except Exception as error:
            service_logger().critical(f"*** Insert incident batch list into database failed: {error} ")
