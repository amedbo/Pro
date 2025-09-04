import enum
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base

class IndicatorType(enum.Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    url = "url"
    domain = "domain"
    file_hash_md5 = "file_hash_md5"
    file_hash_sha1 = "file_hash_sha1"
    file_hash_sha256 = "file_hash_sha256"

class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    threat_class = Column(String, default="unknown") # e.g., ransomware, phishing, apt
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    indicators = relationship("Indicator", back_populates="threat")

class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(Enum(IndicatorType))
    value = Column(String, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    threat = relationship("Threat", back_populates="indicators")
