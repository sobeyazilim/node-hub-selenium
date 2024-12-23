# primary libraries
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.pool import Pool
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from contextlib import contextmanager

import os

# schemas
from core.schemas import database_sqlalchemy_database_uri, database_debug_mode, database_pool_size, database_max_overflow

# services
from core.services.serviceLogger import service_logger, service_logger_debug


# Create engine
engine = create_engine(
    database_sqlalchemy_database_uri,
    echo = database_debug_mode,
    pool_size = database_pool_size,
    max_overflow = database_max_overflow
)

# Create session
SessionLocal = sessionmaker(autoflush=True, bind=engine, expire_on_commit=False)

# create data connector
dbprovider = SessionLocal()

# Create base
dbBase = declarative_base()

class DatabaseConnectionError(Exception):
    """Custom exception for database connection errors."""
    pass

def check_database_connection(engine: Engine) -> bool:
    try:
        conn = engine.connect()
        conn.close()
        return True
    
    except Exception as e:
        service_logger().error(f"Error checking database connection: {e}")
        return False
    
def initialize_db():
    """Initialize the database by creating all tables."""
    try:

        if not check_database_connection(engine):
            raise DatabaseConnectionError("Connection pool is not available. Initialization failed.")

        dbBase.metadata.create_all(bind=engine)
        dbprovider.commit()
    
    except DatabaseConnectionError as e:
        service_logger().error(f"Error initializing the database: {e}")
        os._exit(1)
    
    except Exception as e:
        dbprovider.rollback()
        service_logger().error(f"Error initializing the database: {e}")
        raise