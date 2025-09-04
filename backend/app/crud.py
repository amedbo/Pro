from sqlalchemy.orm import Session
from . import models, schemas

# Threat CRUD operations
def get_threat(db: Session, threat_id: int):
    return db.query(models.Threat).filter(models.Threat.id == threat_id).first()

def get_threat_by_name(db: Session, name: str):
    return db.query(models.Threat).filter(models.Threat.name == name).first()

def get_threats(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Threat).offset(skip).limit(limit).all()

def create_threat(db: Session, threat: schemas.ThreatCreate):
    db_threat = models.Threat(
        name=threat.name,
        description=threat.description,
        threat_class=threat.threat_class or "unknown" # Set default if not provided
    )
    db.add(db_threat)
    db.commit()
    db.refresh(db_threat)
    return db_threat

def update_threat_class(db: Session, threat_id: int, threat_class: str):
    db_threat = get_threat(db, threat_id)
    if db_threat:
        db_threat.threat_class = threat_class
        db.commit()
        db.refresh(db_threat)
    return db_threat

# Indicator CRUD operations
def get_indicators(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Indicator).offset(skip).limit(limit).all()

def create_threat_indicator(db: Session, indicator: schemas.IndicatorCreate, threat_id: int):
    db_indicator = models.Indicator(**indicator.model_dump(), threat_id=threat_id)
    db.add(db_indicator)
    db.commit()
    db.refresh(db_indicator)
    return db_indicator
