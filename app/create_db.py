from app.db.session import Base, engine
from app.db.models.user import User

print("Creating tables...")
Base.metadata.create_all(bind=engine)
print("Done.")
