from sqlalchemy import Column, String,  Text, DateTime, Boolean, Integer, JSON, event, inspect, func, TIMESTAMP, LargeBinary
from datetime import datetime


from core.providers.dbprovider import dbBase, dbprovider
from core.classes.class_configuration import class_configuration
from core.services.serviceLogger import service_logger


class ModelCredentials(dbBase):
    __tablename__ = 'case_library'
    _first_public_id = int(class_configuration().return_database_public_id_dict()['PID_CREDENTIALS'])

    id = Column(Integer, primary_key=True, index=True)

    public_id = Column(
        String,
        nullable=False,
        unique=True,
        primary_key=True,
    )       
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)

    
    def __repr__(self):
        return f"<Credentials(username={self.username})>"

    @staticmethod
    def datetime_to_string(dt: datetime) -> str:
        return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else None

    def as_dict(self) -> dict:
        """Convert the model instance to a dictionary."""
        columns = {}
        for column in inspect(self).mapper.column_attrs:
            value = getattr(self, column.key, None)
            # Eğer değer bir datetime nesnesiyse, string'e dönüştür
            if isinstance(value, datetime):
                value = self.datetime_to_string(value)
            columns[column.key] = value
        return columns
    def __init__(self, **kwargs):
        if 'public_id' not in kwargs:
            try:
                kwargs['public_id'] = self.generate_public_id()
            except Exception as e:
                service_logger().error(f"Error during __init__: {e}")
        super().__init__(**kwargs)

    @classmethod
    def generate_public_id(cls):
        new_public_id = str(cls._first_public_id + 1)

        try:
            # Check if the partition table exists
            inspector = inspect(dbprovider.bind)

            # Check if the partition table exists
            if inspector.has_table(ModelCredentials.__tablename__):

                last_object = dbprovider.query(cls) \
                    .order_by(cls.public_id.desc()) \
                    .first()

                if last_object:
                    new_public_id = str(int(last_object.public_id) + 1)

            else:
                # Table does not exist, create it or handle the error accordingly
                service_logger().warning("Table credentials does not exist!")

        except Exception as e:
            service_logger().warning(f"Error generating public ID: {e}")

        cls._first_public_id += 1  # Increment the first_public_id

        return new_public_id
