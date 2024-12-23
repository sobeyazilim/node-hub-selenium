# primary libraries
from sqlalchemy import Column, Integer, String, DateTime, event, inspect, JSON
from datetime import datetime, timedelta
import secrets



# providers
from core.providers.dbprovider import dbprovider, dbBase

# class
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceLogger import service_logger, service_logger_debug

# definitions
first_public_id = int(class_configuration().return_database_public_id_dict()['PID_CYBERPOT_DEPLOYMENTS'])


class ModelCyberPotDeployments(dbBase):
    __tablename__ = 'cyberpot_deployments'
    __table_args__ = {'quote': False, 'extend_existing': True}

    id = Column(Integer, primary_key=True)
    public_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False, unique=True)
    container_id = Column(String, nullable=False)
    decoy = Column(String, nullable=False)
    port = Column(String, nullable=False)
    last_started = Column(DateTime, nullable=True,)
    resource_usages = Column(JSON, nullable=False)
    action_status = Column(String, nullable=False) # Running, Exited, Paused

    def __init__(self, **kwargs):
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
                kwargs['container_id'] = self.generate_container_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")

        super().__init__(**kwargs)

    def __repr__(self):
        deployments_dict = {
            "public_id": self.public_id,
            "name": self.name,
            "container_id": self.container_id,
            "decoy": self.decoy,
            "port": self.port,
            "last_started": self.last_started,
            "resource_usages": self.resource_usages,
            "action_status": self.action_status
        }
        return f'<Table/Cyberpot/Deployments ---> {deployments_dict}\n'

    def as_dict(self) -> dict:
        """Convert the model instance to a dictionary."""
        columns = {}
        for column in inspect(self).mapper.column_attrs:
            value = getattr(self, column.key, None)
            if isinstance(value, DateTime):
                value = self.datetime_to_string(value)
            columns[column.key] = value
        return columns
    
    @staticmethod
    def generate_public_id():
        global first_public_id
        new_public_id = str(first_public_id+1)

        try:
            # Check if the partition table exists
            inspector = inspect(dbprovider.bind)

            # Check if the partition table exists
            if inspector.has_table(ModelCyberPotDeployments.__tablename__):

                last_object = dbprovider.query(ModelCyberPotDeployments) \
                    .order_by(ModelCyberPotDeployments.public_id.desc()) \
                    .first()
                
                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)

            else:
                # Table does not exist, create it or handle the error accordingly
                service_logger().warning("Table cyberpot_deployments does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        first_public_id += 1  # Increment the first_public_id
        
        return new_public_id
    
    @staticmethod
    def generate_container_id():
        """Generate a Docker-like container ID (64-character hexadecimal string)."""
        return ''.join(secrets.token_hex(32))
    
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
            instance = dbprovider.query(ModelCyberPotDeployments).get(self.id)
            if instance:
                dbprovider.delete(instance)
                dbprovider.commit()
        except Exception as e:
            service_logger().error(f"Error during _delete: {e}")
            dbprovider.rollback()

# Event listener for after_create
@event.listens_for(ModelCyberPotDeployments.__table__, 'after_create')  # type: ignore
def aftercreate_model_cyberpot_decoys(*args, **kwargs):
    """Insert initial elements into table after created"""

    service_logger().info("after_create: ModelCyberPotDeployments triggered")

    try:

        predefined_deployments = [
            {
                "name": "adbhoney deployment", 
                "decoy": "adbhoney",
                "port": "5555",
                "last_started": (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S"),
                "resource_usages": {
                    "cpu": "0%",
                    "memory": "0%",
                    "disk": "0%",
                },
                "action_status": "Exited"
            },
            {
                "name": "ciscoasa deployment", 
                "decoy": "ciscoasa", 
                "port": "22", 
                "last_started": (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S"),
                "resource_usages": {
                    "cpu": "0%",
                    "memory": "0%",
                    "disk": "0%",
                },
                "action_status": "Exited"
            },
            {
                "name": "conpot deployment", 
                "decoy": "conpot", 
                "port": "80", 
                "last_started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "resource_usages": {
                    "cpu": "2%",
                    "memory": "1.5%",
                    "disk": "5%",
                },
                "action_status": "Running"
            },
            {
                "name": "cowrie deployment", 
                "decoy": "cowrie", 
                "port": "22", 
                "last_started": (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d %H:%M:%S"),
                "resource_usages": {
                    "cpu": "0%",
                    "memory": "0%",
                    "disk": "0%",
                },
                "action_status": "Exited"
            },
            {
                "name": "ddospot deployment", 
                "decoy": "ddospot", 
                "port": "8080", 
                "last_started": (datetime.now() - timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S"),
                "resource_usages": {
                    "cpu": "0%",
                    "memory": "0.5%",
                    "disk": "0%",
                },
                "action_status": "Paused"
            },
        ]

        for deployment in predefined_deployments:
            dbprovider.add(ModelCyberPotDeployments(
                name = deployment["name"],
                decoy = deployment["decoy"],
                port = deployment["port"],
                last_started = deployment["last_started"],
                resource_usages = deployment["resource_usages"],
                action_status = deployment["action_status"]
            ))

    except Exception as e:
        service_logger().error(f"after_create: ModelCyberPotDeployments error: {e}")
