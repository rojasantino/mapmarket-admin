from datetime import datetime
from db import db

class Cart(db.Model):
    __tablename__ = "cart"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    product = db.relationship("Product", backref="cart_items")

    qty = db.Column(db.Integer, nullable=False, default=1)
    shipping = db.Column(db.Numeric(10, 2), nullable=True)
    tax = db.Column(db.Numeric(10, 2), nullable=True)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


