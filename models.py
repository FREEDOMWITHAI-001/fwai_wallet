from datetime import datetime, timezone

from extensions import db


# ---------------------------------------------------------------------------
# Association table: Secret <-> Tag (many-to-many)
# ---------------------------------------------------------------------------
secret_tags = db.Table(
    "sv_secret_tags",
    db.Column("secret_id", db.Integer, db.ForeignKey("sv_secret.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("sv_tag.id"), primary_key=True),
)


# ---------------------------------------------------------------------------
# Models (all prefixed with sv_ to avoid conflicts in shared databases)
# ---------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "sv_user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    secrets = db.relationship("Secret", backref="owner", lazy=True, cascade="all, delete-orphan")


class Secret(db.Model):
    __tablename__ = "sv_secret"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    visibility = db.Column(db.String(10), nullable=False, default="private")
    owner_id = db.Column(db.Integer, db.ForeignKey("sv_user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    fields = db.relationship("SecretField", backref="secret", lazy=True, cascade="all, delete-orphan")
    tags = db.relationship("Tag", secondary=secret_tags, backref=db.backref("secrets", lazy=True))


class SecretField(db.Model):
    __tablename__ = "sv_secret_field"
    id = db.Column(db.Integer, primary_key=True)
    secret_id = db.Column(db.Integer, db.ForeignKey("sv_secret.id"), nullable=False)
    field_name = db.Column(db.String(200), nullable=False)
    field_value_encrypted = db.Column(db.Text, nullable=False)


class Tag(db.Model):
    __tablename__ = "sv_tag"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    color = db.Column(db.String(7), nullable=False, default="#6366f1")
    created_by = db.Column(db.Integer, db.ForeignKey("sv_user.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class AuditLog(db.Model):
    __tablename__ = "sv_audit_log"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("sv_user.id"), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text, default="")
    ip_address = db.Column(db.String(45), default="")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class PolicyConfig(db.Model):
    __tablename__ = "sv_policy_config"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False, default="")
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
