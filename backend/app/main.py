from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from . import crud, models, schemas
from . import analyzer
from .database import SessionLocal, engine

# Create the database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Project Cybersentinel API",
    description="API for the Proactive Threat Intelligence Platform",
    version="0.1.0"
)

# Dependency to get a DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"message": "Welcome to the Cybersentinel API"}

# Placeholder for future endpoints to be developed in Step 2
@app.post("/threats/", response_model=schemas.Threat)
def create_threat_endpoint(threat: schemas.ThreatCreate, db: Session = Depends(get_db)):
    db_threat_check = crud.get_threat_by_name(db, name=threat.name)
    if db_threat_check:
        raise HTTPException(status_code=400, detail="Threat name already registered")

    # Create the threat first
    db_threat = crud.create_threat(db=db, threat=threat)

    # --- Start Advanced Analysis ---
    if db_threat.description:
        # 1. Classify threat type if not provided
        if not threat.threat_class:
            print("No threat class provided, attempting auto-classification...")
            classified_class = analyzer.classify_threat(db_threat.description)
            if classified_class != "unknown":
                print(f"Auto-classified threat as: {classified_class}")
                crud.update_threat_class(db, db_threat.id, classified_class)

        # 2. Extract IOCs with NER and add them to the threat
        print("Extracting IOCs from description with NER model...")
        iocs_to_add = analyzer.extract_iocs_with_ner(db_threat.description)
        for ioc_data in iocs_to_add:
            # Convert dict to schema object before creating
            indicator_schema = schemas.IndicatorCreate(**ioc_data)
            crud.create_threat_indicator(db=db, indicator=indicator_schema, threat_id=db_threat.id)
    # --- End Advanced Analysis ---

    # Refresh the threat object to get all the new indicators and updated class
    db.refresh(db_threat)
    return db_threat

@app.get("/threats/", response_model=List[schemas.Threat])
def read_threats_endpoint(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    threats = crud.get_threats(db, skip=skip, limit=limit)
    return threats

@app.get("/threats/{threat_id}", response_model=schemas.Threat)
def read_threat_endpoint(threat_id: int, db: Session = Depends(get_db)):
    db_threat = crud.get_threat(db, threat_id=threat_id)
    if db_threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    return db_threat

@app.post("/threats/{threat_id}/indicators/", response_model=schemas.Indicator)
def create_indicator_for_threat_endpoint(
    threat_id: int, indicator: schemas.IndicatorCreate, db: Session = Depends(get_db)
):
    db_threat = crud.get_threat(db, threat_id=threat_id)
    if db_threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    return crud.create_threat_indicator(db=db, indicator=indicator, threat_id=threat_id)

@app.get("/indicators/", response_model=List[schemas.Indicator])
def read_indicators_endpoint(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    indicators = crud.get_indicators(db, skip=skip, limit=limit)
    return indicators
