"""Vault Agent — Secret CRUD, encryption, tag management, search."""

import os
from datetime import datetime, timezone

from cryptography.fernet import Fernet

from extensions import db
from models import Secret, SecretField, Tag, secret_tags

# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
_raw_key = os.environ.get("FERNET_KEY", "").strip()
if not _raw_key:
    _raw_key = Fernet.generate_key().decode()
    print("[WARN] FERNET_KEY not set, generated ephemeral key. Data will not persist across restarts.")
FERNET_KEY = _raw_key
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)


def encrypt_value(plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()


def decrypted_value_for_field(field: SecretField) -> str:
    return decrypt_value(field.field_value_encrypted)


# ---------------------------------------------------------------------------
# Field parsing
# ---------------------------------------------------------------------------
def parse_fields(form, max_fields: int = 50) -> list[tuple[str, str]]:
    """Parse dynamic key-value fields from a form."""
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
        if idx > max_fields:
            break
    return fields


# ---------------------------------------------------------------------------
# Access helpers
# ---------------------------------------------------------------------------
def can_view(secret: Secret, user_id: int, role: str) -> bool:
    if role == "admin":
        return True
    if secret.owner_id == user_id:
        return True
    if secret.visibility == "public":
        return True
    return False


def can_edit(secret: Secret, user_id: int, role: str) -> bool:
    if role == "admin":
        return True
    return secret.owner_id == user_id


# ---------------------------------------------------------------------------
# Secret CRUD
# ---------------------------------------------------------------------------
def create_secret(owner_id: int, name: str, description: str, visibility: str,
                  fields: list[tuple[str, str]], tag_names: list[str] | None = None) -> Secret:
    secret = Secret(
        name=name,
        description=description,
        visibility=visibility,
        owner_id=owner_id,
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

    if tag_names:
        secret.tags = get_or_create_tags(tag_names, created_by=owner_id)

    db.session.commit()
    return secret


def update_secret(secret: Secret, name: str, description: str, visibility: str,
                  fields: list[tuple[str, str]], tag_names: list[str] | None = None) -> Secret:
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

    # Replace tags
    if tag_names is not None:
        secret.tags = get_or_create_tags(tag_names, created_by=secret.owner_id)
    else:
        secret.tags = []

    db.session.commit()
    return secret


def delete_secret(secret: Secret) -> None:
    db.session.delete(secret)
    db.session.commit()


def get_secret(secret_id: int) -> Secret | None:
    return db.session.get(Secret, secret_id)


def get_decrypted_fields(secret: Secret) -> list[tuple[str, str]]:
    return [(f.field_name, decrypt_value(f.field_value_encrypted)) for f in secret.fields]


# ---------------------------------------------------------------------------
# Dashboard queries
# ---------------------------------------------------------------------------
def list_secrets_for_user(user_id: int, is_admin: bool, tag_filter: str | None = None):
    """Return (my_secrets, other_secrets) for the dashboard."""
    my_q = Secret.query.filter_by(owner_id=user_id)
    if tag_filter:
        my_q = my_q.filter(Secret.tags.any(Tag.name == tag_filter))
    my_secrets = my_q.order_by(Secret.updated_at.desc()).all()

    if is_admin:
        other_q = Secret.query.filter(Secret.owner_id != user_id)
    else:
        other_q = Secret.query.filter(Secret.visibility == "public", Secret.owner_id != user_id)
    if tag_filter:
        other_q = other_q.filter(Secret.tags.any(Tag.name == tag_filter))
    other_secrets = other_q.order_by(Secret.updated_at.desc()).all()

    return my_secrets, other_secrets


def search_secrets(user_id: int, query: str, is_admin: bool, tag_filter: str | None = None):
    """Full-text search across secret names and descriptions."""
    pattern = f"%{query}%"
    base_q = Secret.query.filter(
        db.or_(Secret.name.ilike(pattern), Secret.description.ilike(pattern))
    )
    if not is_admin:
        base_q = base_q.filter(
            db.or_(Secret.owner_id == user_id, Secret.visibility == "public")
        )
    if tag_filter:
        base_q = base_q.filter(Secret.tags.any(Tag.name == tag_filter))
    return base_q.order_by(Secret.updated_at.desc()).all()


# ---------------------------------------------------------------------------
# Tag management
# ---------------------------------------------------------------------------
def get_or_create_tags(tag_names: list[str], created_by: int | None = None) -> list[Tag]:
    """Get existing tags or create new ones. Names are normalized to lowercase."""
    tags = []
    for raw_name in tag_names:
        name = raw_name.strip().lower()
        if not name:
            continue
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            tag = Tag(name=name, created_by=created_by)
            db.session.add(tag)
            db.session.flush()
        tags.append(tag)
    return tags


def list_all_tags() -> list[Tag]:
    return Tag.query.order_by(Tag.name).all()


def search_tags(query: str, limit: int = 20) -> list[Tag]:
    """Search tags by name prefix for typeahead autocomplete."""
    return Tag.query.filter(Tag.name.ilike(f"%{query}%")).order_by(Tag.name).limit(limit).all()


def delete_tag(tag_id: int) -> Tag | None:
    tag = db.session.get(Tag, tag_id)
    if tag:
        db.session.delete(tag)
        db.session.commit()
    return tag


def update_tag_color(tag_id: int, color: str) -> Tag | None:
    tag = db.session.get(Tag, tag_id)
    if tag:
        tag.color = color
        db.session.commit()
    return tag
