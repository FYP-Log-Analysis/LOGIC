from sqlalchemy import Column, Integer, String, DateTime, JSON
from main import Base

class NormalizedLog(Base):
    __tablename__ = "normalized_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_id = Column(Integer)
    source = Column(String)
    user_name = Column(String)
    computer = Column(String)
    process_path = Column(String)
    command_line = Column(String)
    category = Column(String)
    summary = Column(String)
    raw = Column(JSON)
