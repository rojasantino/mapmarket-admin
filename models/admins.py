from datetime import datetime
from db import db
from sqlalchemy import event, text

class Admin(db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    products = db.relationship("Product", backref="seller", lazy=True)
    user_id = db.Column(db.String(20), unique=True, nullable=True)  # e.g., MMID-001
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(256), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default="admin", nullable=False)
    is_main_admin = db.Column(db.Boolean, default=False)  # <-- main admin flag
    status = db.Column(db.String(10), default="inactive", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Admin {self.email} - main:{self.is_main_admin} - {self.status}>"

# Auto-generate user_id
@event.listens_for(Admin, "before_insert")
def generate_admin_user_id(mapper, connection, target):
    if target.role.lower() == "admin":
        last_admin = connection.execute(
            text("SELECT user_id FROM admins WHERE role='admin' ORDER BY id DESC LIMIT 1")
        ).fetchone()
        if last_admin and last_admin[0]:
            last_num = int(last_admin[0].split('-')[1])
            target.user_id = f"MMID-{last_num + 1:03d}"
        else:
            target.user_id = "MMID-001"
    else:
        target.user_id = None
