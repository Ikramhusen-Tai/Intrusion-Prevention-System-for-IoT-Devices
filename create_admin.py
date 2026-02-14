from app import app, db
from models import Admin
from werkzeug.security import generate_password_hash

with app.app_context():
    # ensure tables exist
    db.create_all()

    username = "admin"
    raw_password = "inse6170"

    existing = Admin.query.filter_by(username=username).first()
    if not existing:
        password_hash = generate_password_hash(raw_password)
        admin = Admin(username=username, password_hash=password_hash)
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user created (username={username}, password={raw_password})")
    else:
        print("Admin already exists")
