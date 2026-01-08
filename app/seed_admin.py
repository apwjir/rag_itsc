from app.db.session import SessionLocal
from app.db.models.user import User
from app.core.security import get_password_hash
from decouple import config

def seed_admin():
    db = SessionLocal()

    admin_username = config("ADMIN_USERNAME")
    admin_password = config("ADMIN_PASSWORD")

    # เช็คก่อนว่ามี admin แล้วหรือยัง
    existing = db.query(User).filter(User.username == admin_username).first()
    if existing:
        print("Admin already exists.")
        return

    # สร้าง admin user ใหม่
    admin_user = User(
        username=admin_username,
        hashed_password=get_password_hash(admin_password),
        role="admin",
    )

    db.add(admin_user)
    db.commit()
    db.close()

    print("Admin user created successfully!")

if __name__ == "__main__":
    seed_admin()
