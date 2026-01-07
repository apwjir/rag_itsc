from sqlalchemy import Column, Integer, Boolean
from app.db.session import Base

class AutoAnalyzeSetting(Base):
    __tablename__ = "auto_analyze_settings"

    id = Column(Integer, primary_key=True, index=True)
    enabled = Column(Boolean, default=False, nullable=False)

    # rate control (simple + enough)
    batch_size = Column(Integer, default=1, nullable=False) 
    interval_sec = Column(Integer, default=4, nullable=False)   
