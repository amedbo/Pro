from app.database import engine, Base
# We need to import the models so that Base knows about them
from app.models import Threat, Indicator

print("Attempting to create database tables...")
try:
    Base.metadata.create_all(bind=engine)
    print("Database tables should be created now.")
except Exception as e:
    print("An error occurred:")
    print(e)
