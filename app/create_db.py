# app/services/create_db.py
from app.db.session import Base, engine
from app.db.models.user import User
from app.db.models.auto_analyze_setting import AutoAnalyzeSetting

def init_db():
    print("Creating tables...")
    Base.metadata.create_all(bind=engine)
    print("Done.")

if __name__ == "__main__":
    init_db()
