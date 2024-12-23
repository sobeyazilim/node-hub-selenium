# Primary libraries
from sqlalchemy import text
from datetime import datetime, timedelta

# providers
from core.providers.dbprovider import dbprovider

# class
from core.classes.class_configuration import class_configuration

# services
from core.services.serviceLogger import service_logger, service_logger_debug

class PartitionManager:
    def __init__(self, connection):
        self.connection = connection
        self.database_retention_table_name = class_configuration().return_database_retention_table_name()
        self.database_max_allowed_table_size = class_configuration().return_database_max_allowed_table_size()
        self.database_retention_period_days = class_configuration().return_database_retention_period_days()
        self.database_portion_of_records_to_delete = class_configuration().return_database_portion_of_records_to_delete()
        self.database_identifier_to_delete_records = class_configuration().return_database_identifier_to_delete_records()

    def create_partition(self, date: datetime):
        partition_name = f"{self.database_retention_table_name}_{date.strftime('%Y%m%d')}"

        create_partition_sql = text(f"""
            CREATE TABLE IF NOT EXISTS {partition_name}
            PARTITION OF {self.database_retention_table_name}
            FOR VALUES FROM ('{date.strftime('%Y-%m-%d')}') TO ('{(date + timedelta(days=1)).strftime('%Y-%m-%d')}');
        """)

        try:
            # Execute the SQL to create the partition
            self.connection.execute(create_partition_sql)
            # Commit the transaction
            self.connection.commit()
            service_logger().info(f"Partition {partition_name} created or already exists.")
        
        except Exception as e:
            # Rollback the transaction in case of an error
            # self.connection.rollback()
            service_logger().error(f"Error creating partition: {e}")

    def create_partition_for_today(self):
        today = datetime.now()
        self.create_partition(today)
        
    def create_partition_for_tomorrow(self):
        tomorrow = datetime.now() + timedelta(days=1)
        self.create_partition(tomorrow)

    def size_check(self):
        max_size_bytes = self.database_max_allowed_table_size * 1024 * 1024  # Convert MB to bytes

        table_size_sql = text(f"""
            SELECT sum(pg_total_relation_size(relid)) 
            FROM pg_partition_tree('{self.database_retention_table_name}') AS pt(relid);
        """)

        try:
            table_size = self.connection.execute(table_size_sql).scalar()
            percentage_used = (table_size / max_size_bytes) * 100

            if table_size > max_size_bytes:
                service_logger().warning(f"Table {self.database_retention_table_name} reached max size. Deleting old records. percentage_used: {percentage_used}")
                self._delete_oldest_records()
            else:
                service_logger().info(f"Table {self.database_retention_table_name} size in bytes: {table_size} max_size: {max_size_bytes} percentage_used: {percentage_used}")

        except Exception as e:
            service_logger().error(f"Error during {self.database_retention_table_name} table size check: {e}")

    def drop_old_partitions(self):
        try:

            cutoff_date = datetime.now() - timedelta(days=self.database_retention_period_days)

            partitions_sql = text(f"""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_name LIKE '{self.database_retention_table_name}_%'
                AND table_name ~ '{self.database_retention_table_name}_\\d{{4}}\\d{{2}}\\d{{2}}'
                AND to_date(regexp_replace(table_name, '{self.database_retention_table_name}_', ''), 'YYYYMMDD') < '{cutoff_date.strftime('%Y-%m-%d')}';
            """)

            partitions = self.connection.execute(partitions_sql).fetchall()
            
            for partition in partitions:
                partition_name = partition[0]
                service_logger().info(f"Partition {partition_name} will be dropped.")
                self._drop_partition(partition_name)

        except Exception as e:
            service_logger().error(f"Error dropping old partitions: {e}")

        else:
            service_logger().info("Old partitions dropped if exists.")

    def _delete_oldest_records(self):
        oldest_records_sql = text(f"""                         
            DELETE FROM {self.database_retention_table_name}
            WHERE {self.database_identifier_to_delete_records} IN (
                SELECT {self.database_identifier_to_delete_records}
                FROM {self.database_retention_table_name}
                ORDER BY {self.database_identifier_to_delete_records} ASC
                LIMIT {self.database_portion_of_records_to_delete}
            );
        """)

        try:
            self.connection.execute(oldest_records_sql)
            self.connection.commit()
            service_logger().info(f"Records deleted to maintain table size under {self.database_max_allowed_table_size} MB.")
        
        except Exception as e:
            # self.connection.rollback()
            service_logger().error(f"Error deleting oldest records: {e}")

    def _drop_partition(self, partition_name):
        drop_partition_sql = text(f"DROP TABLE IF EXISTS {partition_name};")
        try:
            self.connection.execute(drop_partition_sql)
            self.connection.commit()
            service_logger().info(f"Partition {partition_name} dropped if it existed.")
        except Exception as e:
            # self.connection.rollback()
            service_logger().error(f"Error dropping partition: {e}")

def scheduled_task():
    try:
        manager = PartitionManager(dbprovider)
        manager.drop_old_partitions()
        manager.size_check()
        manager.create_partition_for_today()
        manager.create_partition_for_tomorrow()
        
    except Exception as e:
        service_logger().error("An error occurred during the scheduled task: %s", e, exc_info=True)