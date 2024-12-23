# primary libraries
from sqlalchemy import Boolean, Column, Integer, String, DateTime, Date, event
from sqlalchemy.orm import Session
from fastapi import HTTPException
from typing import Any
from datetime import datetime

# providers
from core.providers.dbprovider import dbBase, dbprovider

# history>logins models
class ModelHistoryLogin(dbBase):
    """history/logins model."""
    __tablename__ = 'history_login'
    __table_args__ = { 'quote': False, 'extend_existing': True }
    id = Column(
        Integer,
        primary_key=True
    )
    login_name = Column(
        String(100),
        nullable = False,
        unique = False
    )
    stat = Column(
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
    created_on = Column(
        DateTime,
        nullable = False,
        unique = False,
    )
    logout_date = Column(
        DateTime,
        nullable = True,
        unique = False
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def __repr__(self):
        return '<Table/History/Login -- login_name: {}>'.format(self.login_name)

class model_history_login_insert:
    @staticmethod
    def init(pydantic_data: Any, stat: str) -> None:
        """Insert new data element into the database"""
        try:
            data_element = ModelHistoryLogin(
                login_name=pydantic_data.login_name,
                source_ip_address=pydantic_data.source_ip_address,
                source_device=pydantic_data.source_device,
                source_browser=pydantic_data.source_browser,
                source_os=pydantic_data.source_os,
                referer=pydantic_data.referer,
                stat=stat,
                created_on=datetime.now()
            )

            # Insert into the database and commit
            dbprovider.add(data_element)
            dbprovider.commit()
        
        except Exception as e:
            dbprovider.rollback()
            raise HTTPException(status_code=500, detail="An error occurred while inserting data") from e
