from flask import json, request, jsonify, current_app as app
from werkzeug.security import check_password_hash, generate_password_hash
from db import db
from auths import encode_admin_auth_token, admin_auth
from models.admins import Admin
from werkzeug.utils import secure_filename
from models.products import Product
import os



# Folder for uploaded images
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads", "products")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ================= CREATE PRODUCT =================
@app.route("/api/products", methods=["POST"])
@admin_auth
def create_product(current_user):

    if current_user.role != "admin":
        return jsonify({"error": "Only admins can create products"}), 403

    if current_user.status != "active":
        return jsonify({"error": "Inactive admin cannot create products"}), 403

    data = request.form.to_dict()
    data["seller_id"] = current_user.id
    data["seller_name"] = current_user.username

    # ---------- Handle multiple images ----------
    image_filename = []
    if "images" in request.files:
        files = request.files.getlist("images")
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                image_filename.append(filename)

    data["image_filename"] = image_filename

    # ---------- Required fields ----------
    for field in ["title", "category", "price", "stock"]:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    # ---------- Numeric conversions ----------
    numeric_fields = [
        "price", "discount", "discounted_price",
        "tax", "shipping_cost", "shipping_weight"
    ]

    for field in numeric_fields:
        if data.get(field):
            try:
                data[field] = float(data[field])
            except ValueError:
                return jsonify({"error": f"{field} must be numeric"}), 400

    data["stock"] = int(data["stock"])

    # ---------- JSON fields ----------
    if "material" in data:
        data["material"] = json.loads(data["material"])

    if "size" in data:
        data["size"] = json.loads(data["size"])

    if "features" in data:
        data["features"] = data["features"]

    # ---------- Save ----------
    allowed_fields = {c.name for c in Product.__table__.columns if c.name not in ("id", "created_at")}
    product_data = {k: v for k, v in data.items() if k in allowed_fields}

    new_product = Product(**product_data)
    db.session.add(new_product)
    db.session.commit()

    return jsonify({
        "message": "Product created successfully",
        "product_id": new_product.product_id,
        "images": new_product.image_filename
    }), 201


# ================= GET PRODUCTS =================
@app.route("/api/products", methods=["GET"])
@admin_auth
def get_products(current_user):
    query = Product.query

    # Sub-admins see only their own products
    if current_user.role == "admin" and not getattr(current_user, "is_main_admin", False):
        query = query.filter_by(seller_id=current_user.id)

    # Optional filters
    category = request.args.get("category")
    min_price = request.args.get("min_price", type=float)
    max_price = request.args.get("max_price", type=float)

    if category:
        query = query.filter_by(category=category)
    if min_price is not None:
        query = query.filter(Product.price >= min_price)
    if max_price is not None:
        query = query.filter(Product.price <= max_price)

    products = query.all()
    return jsonify([p.to_dict() for p in products]), 200

# ================= UPDATE PRODUCT =================
@app.route("/api/products/<product_id>", methods=["PUT"])
@admin_auth
def update_product(current_user, product_id):
    if current_user.role != "admin":
        return jsonify({"error": "Only admins can update products"}), 403

    # Main admin can update any product, sub-admin only own products
    if getattr(current_user, "is_main_admin", False):
        product = Product.query.filter_by(product_id=product_id).first()
    else:
        product = Product.query.filter_by(product_id=product_id, seller_id=current_user.id).first()

    if not product:
        return jsonify({"error": "Product not found or unauthorized"}), 404

    data = request.json
    for key, value in data.items():
        if hasattr(product, key):
            setattr(product, key, value)

    db.session.commit()
    return jsonify({"message": "Product updated"}), 200

# ================= DELETE PRODUCT =================
@app.route("/api/products/<product_id>", methods=["DELETE"])
@admin_auth
def delete_product(current_user, product_id):
    if current_user.role != "admin":
        return jsonify({"error": "Only admins can delete products"}), 403

    # Main admin can delete any product, sub-admin only own products
    if getattr(current_user, "is_main_admin", False):
        product = Product.query.filter_by(product_id=product_id).first()
    else:
        product = Product.query.filter_by(product_id=product_id, seller_id=current_user.id).first()

    if not product:
        return jsonify({"error": "Product not found or unauthorized"}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Product deleted"}), 200




# ================= SIGNUP MAIN ADMIN =================
@app.route("/api/admin/create-main-admin", methods=["POST"])
def create_main_admin():
    data = request.get_json()

    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        return jsonify({"error": "Email, username and password required"}), 400

    # Ensure only ONE main admin
    if Admin.query.filter_by(is_main_admin=True).first():
        return jsonify({"error": "Main admin already exists"}), 409

    admin = Admin(
        email=email,
        username=username,
        password=generate_password_hash(password),
        role="admin",
        is_main_admin=True,
        status="inactive"
    )

    db.session.add(admin)
    db.session.commit()

    return jsonify({
        "message": "Main admin created successfully",
        "user_id": admin.user_id
    }), 201



# ================= SIGNUP SUB-ADMIN (PUBLIC) =================
@app.route("/api/admin/create-subadmin", methods=["POST"])
def create_subadmin():
    data = request.get_json()

    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        return jsonify({"error": "Email, username and password are required"}), 400

    # Prevent duplicate email or username
    if Admin.query.filter(
        (Admin.email == email) | (Admin.username == username)
    ).first():
        return jsonify({"error": "Admin already exists"}), 400

    subadmin = Admin(
        email=email,
        username=username,
        password=generate_password_hash(password),
        role="admin",
        is_main_admin=False,
        status="inactive"
    )

    db.session.add(subadmin)
    db.session.commit()

    return jsonify({
        "message": "Sub-admin created successfully",
        "subadmin": {
            "id": subadmin.id,
            "user_id": subadmin.user_id,
            "email": subadmin.email,
            "username": subadmin.username,
            "status": subadmin.status
        }
    }), 201



# # ================= SIGNUP SUB-ADMIN =================
# @app.route("/api/admin/create-subadmin", methods=["POST"])
# def create_subadmin():
#     data = request.get_json()
#     email = data.get("email")
#     password = data.get("password")

#     if not email or not password:
#         return jsonify({"error": "Email and password are required"}), 400

#     # Check if email already exists
#     if Admin.query.filter_by(email=email).first():
#         return jsonify({"error": "Admin with this email already exists"}), 400

#     # Hash the password
#     hashed_password = generate_password_hash(password)

#     # Create sub-admin
#     subadmin = Admin(
#         email=email,
#         password=hashed_password,
#         role="admin",
#         is_main_admin=False,  # Always false for sub-admin
#         status="inactive"
#     )

#     db.session.add(subadmin)
#     db.session.commit()

#     return jsonify({
#         "message": "Sub-admin created successfully",
#         "subadmin": {
#             "id": subadmin.id,
#             "user_id": subadmin.user_id,
#             "email": subadmin.email,
#             "role": subadmin.role,
#             "is_main_admin": subadmin.is_main_admin,
#             "status": subadmin.status
#         }
#     }), 201


# ================= ADMIN LOGIN =================

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        return jsonify({"error": "Email, username and password are required"}), 400

    admin = Admin.query.filter_by(email=email, username=username).first()
    if not admin:
        return jsonify({"error": "Admin not found"}), 404

    if not check_password_hash(admin.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Activate admin on login
    admin.status = "active"
    db.session.commit()

    token = encode_admin_auth_token(admin.id)

    return jsonify({
        "message": "Login successful",
        "token": str(token),
        "admin": {
            "id": admin.id,
            "user_id": admin.user_id,
            "username": admin.username,
            "email": admin.email,
            "role": admin.role,
            "is_main_admin": admin.is_main_admin,
            "status": admin.status
        }
    }), 200




# ================= RESET ADMIN PASSWORD =================
@app.route("/api/admin/reset-password/<int:admin_id>", methods=["PUT"])
@admin_auth
def reset_admin_password(current_admin, admin_id):
    data = request.get_json()
    new_password = data.get("new_password")

    if not new_password:
        return jsonify({"error": "New password is required"}), 400

    admin = Admin.query.get(admin_id)
    if not admin:
        return jsonify({"error": "Admin not found"}), 404

    # Main admin can reset anyone
    # Sub-admin can reset only their own password
    if not current_admin.is_main_admin and current_admin.id != admin_id:
        return jsonify({"error": "You can only reset your own password"}), 403

    admin.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({
        "message": f"Password for {admin.email} has been reset successfully."
    }), 200



# ================= ADMIN PROFILE =================

@app.route("/api/admin/profile", methods=["GET"])
@admin_auth  
def admin_profile(current_admin):
    return jsonify({
        "id": current_admin.id,
        "user_id": current_admin.user_id,
        "username": current_admin.username,   # <-- include username
        "email": current_admin.email,
        "role": current_admin.role,
        "is_main_admin": current_admin.is_main_admin,
        "status": current_admin.status,
        "created_at": current_admin.created_at.isoformat()  # optional: send ISO string
    }), 200


# ================= ADMIN LOGOUT =================
@app.route("/api/admin/logout", methods=["POST"])
@admin_auth
def admin_logout(current_admin):
    current_admin.status = "inactive"
    db.session.commit()
    return jsonify({"message": "Logout successful", "status": current_admin.status}), 200






# ✅ Optional: Restrict inactive sub-admins

# @app.route("/api/admin/<int:admin_id>/status", methods=["PUT"])
# @auth
# def toggle_admin_status(current_user, admin_id):
#     if not current_user.is_main_admin:
#         return jsonify({"error": "Only main admin can change admin status"}), 403

#     admin = Admin.query.get(admin_id)
#     if not admin:
#         return jsonify({"error": "Admin not found"}), 404

#     new_status = "active" if admin.status == "inactive" else "inactive"
#     admin.status = new_status
#     db.session.commit()

#     return jsonify({"message": f"Admin {admin.email} is now {new_status}"}), 200




# # ================= CREATE SUB-ADMIN (Main Admin Only) =================
# @app.route("/api/admin/create-subadmin", methods=["POST"])
# @auth
# def create_sub_admin(current_user):
#     # ✅ Only main admin can create sub-admins
#     if not getattr(current_user, "is_main_admin", False):
#         return jsonify({"error": "Only main admin can create sub-admins"}), 403

#     data = request.get_json()
#     email = data.get("email")
#     password = data.get("password")

#     if not email or not password:
#         return jsonify({"error": "Email and password are required"}), 400

#     # ✅ Check if email already exists
#     if Admin.query.filter_by(email=email).first():
#         return jsonify({"error": "Admin with this email already exists"}), 400

#     # ✅ Create sub-admin (non-main)
#     new_admin = Admin(
#         email=email,
#         password=generate_password_hash(password),
#         role="admin",
#         is_main_admin=False,
#         status="active"  # auto-active after creation
#     )

#     db.session.add(new_admin)
#     db.session.commit()

#     return jsonify({
#         "message": "Sub-admin created successfully",
#         "sub_admin": {
#             "id": new_admin.id,
#             "email": new_admin.email,
#             "user_id": new_admin.user_id,
#             "is_main_admin": new_admin.is_main_admin,
#             "status": new_admin.status
#         }
#     }), 201


# curl -X POST http://127.0.0.1:5000/api/admin/create-subadmin \
# -H "Content-Type: application/json" \
# -H "Authorization: Bearer <MAIN_ADMIN_JWT_TOKEN>" \
# -d '{
#   "email": "subadmin2@example.com",
#   "password": "testpass123"
# }'
