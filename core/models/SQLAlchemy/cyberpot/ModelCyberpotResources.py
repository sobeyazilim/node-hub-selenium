# primary libraries
from sqlalchemy import Column, Integer, String, event, Numeric, DateTime, inspect

# providers
from core.providers.dbprovider import dbprovider, dbBase

# class

# services
from core.services.serviceLogger import service_logger, service_logger_debug


class ModelCyberPotResources(dbBase):
    __tablename__ = 'cyberpot_resources'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    attribute = Column(String, nullable=False, unique=True)
    value = Column(Numeric, nullable=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __repr__(self):
        try:
            return f"{{'{self.attribute}': {self.value}}}"
        except Exception as e:
            service_logger().error(f"Error during __repr__: {e}")
            
    def as_dict(self) -> dict:
        """Convert the model instance to a dictionary."""
        columns = {}
        for column in inspect(self).mapper.column_attrs:
            value = getattr(self, column.key, None)
            if isinstance(value, DateTime):
                value = self.datetime_to_string(value)
            columns[column.key] = value
        return columns
    
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
            instance = dbprovider.query(ModelCyberPotResources).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

    # Methods for accessing and modifying fields
    def return_object_attribute(self):
        return self.attribute
    
    def return_object_value(self):
        return self.value
    
    def remove_object(self):
        """Remove object from the database."""
        self._delete()

# Event listener for after_create
@event.listens_for(ModelCyberPotResources.__table__, 'after_create')  # type: ignore
def aftercreate_model_configuration(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelCyberPotResources triggered")

    try:

        dbprovider.add(ModelCyberPotResources(
            attribute='cpu_limit',
            value=1
        ))

        dbprovider.add(ModelCyberPotResources(
            attribute='memory_limit',
            value=2
        ))

        dbprovider.add(ModelCyberPotResources(
            attribute='swap_limit',
            value=512
        ))
        
        dbprovider.add(ModelCyberPotResources(
            attribute='virtual_disk_limit',
            value=128
        ))
        
        dbprovider.add(ModelCyberPotResources(
            attribute='resource_saver',
            value=600
        ))
        
    except Exception as e:
        service_logger().error(f"after_create: ModelCyberPotResources error: {e}")

