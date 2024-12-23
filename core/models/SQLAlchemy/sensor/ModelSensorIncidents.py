# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, DateTime, event, JSON, Date, text
from datetime import date, datetime, timedelta

# providers
from core.providers.dbprovider import dbprovider, dbBase

# services
from core.services.serviceLogger import service_logger, service_logger_debug

# Use the existing dbBase as the declarative base
class ModelSensorIncidents(dbBase):
    __tablename__ = 'sensor_incidents'
    __table_args__ = { 'quote': False, 'extend_existing': True ,'postgresql_partition_by': 'RANGE (ioc_date_created)'}

    ioc_checksum = Column(String, nullable=False, primary_key=True)  # Unique identifier
    ioc_scout = Column(String, nullable=False)
    ioc_classification = Column(String, nullable=False)
    ioc_cyberpot = Column(String, nullable=True)
    ioc_action = Column(String, nullable=False)
    ioc_type = Column(String, nullable=False)
    ioc_device_name = Column(String, nullable=False)
    ioc_vendor_name = Column(String, nullable=False)
    ioc_source_ip = Column(String, nullable=False)
    ioc_destination_ip = Column(String, nullable=False)
    ioc_proto = Column(String, nullable=False)
    ioc_source_port = Column(String, nullable=False)
    ioc_destination_port = Column(String, nullable=False)
    ioc_application = Column(String, nullable=False)
    ioc_application_color = Column(String, nullable=True)
    ioc_traffic_direction = Column(String, nullable=False)
    ioc_geo_lookup_source_stat = Column(String, nullable=False)
    ioc_geo_lookup_destination_stat = Column(String, nullable=False)
    ioc_geo_lookup_metadata = Column(JSON, nullable=True)
    ioc_relation_threat = Column(JSON, nullable=True)
    ioc_relation_malware = Column(JSON, nullable=True)
    ioc_timestamp = Column(String, nullable=False)
    ioc_date_created = Column(Date, default=date.today, nullable=False, primary_key=True)

    def __init__(self, **kwargs):
        print(kwargs)
        super().__init__(**kwargs)

    def __repr__(self):
        return f'<Table/Sensor/Incidents -- checksum: {self.ioc_checksum}>'

#Event listener for after_create
@event.listens_for(ModelSensorIncidents.__table__, 'after_create')  # type: ignore
def aftercreate_ModelSensorIncidents(target, connection, **kwargs):

    service_logger().info("after_create: ModelSensorIncidents triggered")
    
    try:
        current_date = datetime.now()
        partition_name = f"sensor_incidents_{current_date.strftime('%Y%m%d')}"
        retention_table_name = "sensor_incidents"
        
        create_partition_sql = text(f"""
            CREATE TABLE IF NOT EXISTS {partition_name}
            PARTITION OF {retention_table_name}
            FOR VALUES FROM ('{current_date.strftime('%Y-%m-%d')}') TO ('{(current_date + timedelta(days=1)).strftime('%Y-%m-%d')}');
        """)

    
        connection.execute(create_partition_sql)
        service_logger().info(f"Table partition {partition_name} created or already exists.")

    except Exception as e:
        service_logger().error(f"Error creating partition table for {partition_name}: {e}")