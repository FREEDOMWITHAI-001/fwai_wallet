import os
import re
import secrets
from datetime import datetime, timezone
from functools import wraps

from cryptography.fernet import Fernet
import bcrypt
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort, g
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
# Use /tmp on Vercel (read-only filesystem), local instance dir otherwise
_is_vercel = os.environ.get("VERCEL", False)
_db_path = "/tmp/secrets.db" if _is_vercel else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "instance", "secrets.db"
)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{_db_path}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_FIELDS_PER_SECRET"] = 50

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------
FERNET_KEY = os.environ.get("FERNET_KEY", Fernet.generate_key().decode())
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)


def encrypt_value(plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    secrets = db.relationship("Secret", backref="owner", lazy=True, cascade="all, delete-orphan")


class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    visibility = db.Column(db.String(10), nullable=False, default="private")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    fields = db.relationship("SecretField", backref="secret", lazy=True, cascade="all, delete-orphan")


class SecretField(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    secret_id = db.Column(db.Integer, db.ForeignKey("secret.id"), nullable=False)
    field_name = db.Column(db.String(200), nullable=False)
    field_value_encrypted = db.Column(db.Text, nullable=False)

    @property
    def decrypted_value(self):
        return decrypt_value(self.field_value_encrypted)


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Context processor — make current user available in templates
# ---------------------------------------------------------------------------
@app.before_request
def load_current_user():
    g.current_user = None
    if "user_id" in session:
        g.current_user = db.session.get(User, session["user_id"])
        if g.current_user is None:
            session.clear()


@app.context_processor
def inject_user():
    return dict(current_user=g.current_user)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            errors.append("Username may only contain letters, numbers, and underscores.")
        if not email or "@" not in email:
            errors.append("Valid email is required.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if User.query.filter_by(username=username).first():
            errors.append("Username already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("Email already registered.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", username=username, email=email)

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password(password, user.password_hash):
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")
        return render_template("login.html", username=username)

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    is_admin = session.get("role") == "admin"

    if is_admin:
        my_secrets = Secret.query.filter_by(owner_id=user_id).order_by(Secret.updated_at.desc()).all()
        other_secrets = Secret.query.filter(Secret.owner_id != user_id).order_by(Secret.updated_at.desc()).all()
    else:
        my_secrets = Secret.query.filter_by(owner_id=user_id).order_by(Secret.updated_at.desc()).all()
        other_secrets = Secret.query.filter(
            Secret.visibility == "public",
            Secret.owner_id != user_id
        ).order_by(Secret.updated_at.desc()).all()

    return render_template(
        "dashboard.html",
        my_secrets=my_secrets,
        other_secrets=other_secrets,
        is_admin=is_admin,
    )


# ---------------------------------------------------------------------------
# Secret CRUD
# ---------------------------------------------------------------------------
def _parse_fields(form):
    """Parse dynamic key-value fields from the form."""
    fields = []
    idx = 0
    while True:
        name_key = f"field_name_{idx}"
        value_key = f"field_value_{idx}"
        if name_key not in form:
            break
        fname = form[name_key].strip()
        fvalue = form[value_key]
        if fname:
            fields.append((fname, fvalue))
        idx += 1
        if idx > app.config["MAX_FIELDS_PER_SECRET"]:
            break
    return fields


def _can_view(secret):
    if session.get("role") == "admin":
        return True
    if secret.owner_id == session["user_id"]:
        return True
    if secret.visibility == "public":
        return True
    return False


def _can_edit(secret):
    if session.get("role") == "admin":
        return True
    return secret.owner_id == session["user_id"]


@app.route("/secrets/new", methods=["GET", "POST"])
@login_required
def secret_create():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        visibility = request.form.get("visibility", "private")
        fields = _parse_fields(request.form)

        errors = []
        if not name:
            errors.append("Secret name is required.")
        if visibility not in ("public", "private"):
            errors.append("Invalid visibility setting.")
        if not fields:
            errors.append("At least one field is required.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("secret_form.html", editing=False,
                                   name=name, description=description,
                                   visibility=visibility, fields=fields)

        secret = Secret(
            name=name,
            description=description,
            visibility=visibility,
            owner_id=session["user_id"],
        )
        db.session.add(secret)
        db.session.flush()

        for fname, fvalue in fields:
            sf = SecretField(
                secret_id=secret.id,
                field_name=fname,
                field_value_encrypted=encrypt_value(fvalue),
            )
            db.session.add(sf)

        db.session.commit()
        flash("Secret created successfully.", "success")
        return redirect(url_for("secret_view", secret_id=secret.id))

    return render_template("secret_form.html", editing=False, fields=[])


@app.route("/secrets/<int:secret_id>")
@login_required
def secret_view(secret_id):
    secret = db.session.get(Secret, secret_id)
    if not secret:
        abort(404)
    if not _can_view(secret):
        abort(403)

    decrypted_fields = []
    for f in secret.fields:
        decrypted_fields.append((f.field_name, f.decrypted_value))

    return render_template(
        "secret_view.html",
        secret=secret,
        fields=decrypted_fields,
        can_edit=_can_edit(secret),
    )


@app.route("/secrets/<int:secret_id>/edit", methods=["GET", "POST"])
@login_required
def secret_edit(secret_id):
    secret = db.session.get(Secret, secret_id)
    if not secret:
        abort(404)
    if not _can_edit(secret):
        abort(403)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        visibility = request.form.get("visibility", "private")
        fields = _parse_fields(request.form)

        errors = []
        if not name:
            errors.append("Secret name is required.")
        if visibility not in ("public", "private"):
            errors.append("Invalid visibility setting.")
        if not fields:
            errors.append("At least one field is required.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("secret_form.html", editing=True,
                                   secret=secret, name=name,
                                   description=description,
                                   visibility=visibility, fields=fields)

        secret.name = name
        secret.description = description
        secret.visibility = visibility
        secret.updated_at = datetime.now(timezone.utc)

        # Replace all fields
        SecretField.query.filter_by(secret_id=secret.id).delete()
        for fname, fvalue in fields:
            sf = SecretField(
                secret_id=secret.id,
                field_name=fname,
                field_value_encrypted=encrypt_value(fvalue),
            )
            db.session.add(sf)

        db.session.commit()
        flash("Secret updated successfully.", "success")
        return redirect(url_for("secret_view", secret_id=secret.id))

    # GET — populate form with existing data
    fields = [(f.field_name, f.decrypted_value) for f in secret.fields]
    return render_template("secret_form.html", editing=True, secret=secret,
                           name=secret.name, description=secret.description,
                           visibility=secret.visibility, fields=fields)


@app.route("/secrets/<int:secret_id>/delete", methods=["POST"])
@login_required
def secret_delete(secret_id):
    secret = db.session.get(Secret, secret_id)
    if not secret:
        abort(404)
    if not _can_edit(secret):
        abort(403)

    db.session.delete(secret)
    db.session.commit()
    flash("Secret deleted.", "info")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/toggle-role", methods=["POST"])
@admin_required
def admin_toggle_role(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == session["user_id"]:
        flash("You cannot change your own role.", "warning")
        return redirect(url_for("admin_users"))

    user.role = "user" if user.role == "admin" else "admin"
    db.session.commit()
    flash(f"{user.username} is now a{'n admin' if user.role == 'admin' else ' regular user'}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == session["user_id"]:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("admin_users"))

    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} deleted.", "info")
    return redirect(url_for("admin_users"))


@app.route("/admin/secrets")
@admin_required
def admin_secrets():
    secrets_list = Secret.query.order_by(Secret.updated_at.desc()).all()
    return render_template("admin_secrets.html", secrets=secrets_list)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access denied."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


# ---------------------------------------------------------------------------
# Bootstrap admin + DB creation
# ---------------------------------------------------------------------------
def init_app():
    with app.app_context():
        db.create_all()

        # Enable WAL mode for better concurrent read performance
        with db.engine.connect() as conn:
            conn.execute(db.text("PRAGMA journal_mode=WAL"))
            conn.commit()

        # Create default admin if none exists
        if not User.query.filter_by(role="admin").first():
            admin_user = os.environ.get("ADMIN_USERNAME", "admin")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "admin1234")
            admin_email = os.environ.get("ADMIN_EMAIL", "admin@vault.local")
            admin = User(
                username=admin_user,
                email=admin_email,
                password_hash=hash_password(admin_pass),
                role="admin",
            )
            db.session.add(admin)
            db.session.commit()
            print(f"[INIT] Admin user '{admin_user}' created.")


init_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
