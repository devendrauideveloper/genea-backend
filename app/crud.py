# app/crud.py
from sqlalchemy.orm import Session  # type: ignore
import json
from sqlalchemy import select, func  # type: ignore
from sqlalchemy.exc import IntegrityError  # type: ignore
from app.models import User, Customer, Draft
from app.security import hash_password  # still used for *users* (not customers)


# -------------------
# Users
# -------------------

def get_user_by_username(db: Session, username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    return db.execute(stmt).scalar_one_or_none()

def get_user_by_email(db: Session, email: str) -> User | None:
    email_norm = email.lower()
    stmt = select(User).where(func.lower(User.email) == email_norm)
    return db.execute(stmt).scalar_one_or_none()

# def create_user(db: Session, *, name: str, username: str, email: str, password: str) -> User:
#     user = User(
#         name=name.strip(),
#         username=username.strip(),
#         email=email.strip().lower(),        # normalize
#         password_hash=hash_password(password),
#     )
#     db.add(user)
#     db.commit()
#     db.refresh(user)
#     return user

def create_user(db, name, username, email, password):
    user = User(
        name=name,
        username=username,
        email=email,
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user





def get_users(db: Session, skip: int = 0, limit: int = 100) -> list[User]:
    stmt = select(User).offset(skip).limit(limit)
    return db.execute(stmt).scalars().all()

def get_user(db: Session, user_id: int) -> User | None:
    stmt = select(User).where(User.id == user_id)
    return db.execute(stmt).scalar_one_or_none()

# -------------------
# Customers
# -------------------

def get_customer_by_name(db: Session, name: str) -> Customer | None:
    stmt = select(Customer).where(func.lower(Customer.name) == name.lower())
    return db.execute(stmt).scalar_one_or_none()

def create_customer(
    db: Session,
    *,
    name: str,
    auth_method: str,
    username: str | None,
    secret_plain: str,   # password or token from the UI
    created_by_user_id: int,
    customer_uuid: str | None = None,
) -> Customer:
    customer = Customer(
        name=name.strip(),
        auth_method=auth_method,
        username=(username.strip() if username else None),
        customer_uuid=(customer_uuid.strip() if customer_uuid else None),
        # IMPORTANT: As requested, store the *raw* secret here (no hashing).
        secret_hash=secret_plain,
        created_by_user_id=created_by_user_id,
        token_ciphertext=None,  # unused for now
    )
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer

def get_customers(
    db: Session,
    *,
    created_by_user_id: int | None = None,
    skip: int = 0,
    limit: int = 100
) -> list[Customer]:
    stmt = select(Customer).order_by(Customer.id.desc()).offset(skip).limit(limit)
    if created_by_user_id is not None:
        stmt = select(Customer).where(Customer.created_by_user_id == created_by_user_id)\
                               .order_by(Customer.id.desc())\
                               .offset(skip).limit(limit)
    return db.execute(stmt).scalars().all()

def get_customer(db: Session, customer_id: int) -> Customer | None:
    stmt = select(Customer).where(Customer.id == customer_id)
    return db.execute(stmt).scalar_one_or_none()

def update_customer(
    db: Session,
    customer_id: int,
    *,
    name: str | None = None,
    auth_method: str | None = None,
    username: str | None = None,
    secret_plain: str | None = None,
    customer_uuid: str | None = None,
) -> Customer | None:
    obj = db.get(Customer, customer_id)
    if not obj:
        return None
    if name is not None:
        obj.name = name.strip()
    if auth_method is not None:
        obj.auth_method = auth_method
    if username is not None:
        obj.username = username.strip() if username else None
    if secret_plain is not None:
        # IMPORTANT: As requested, store the *raw* secret here (no hashing).
        obj.secret_hash = secret_plain
    if customer_uuid is not None:
        obj.customer_uuid = customer_uuid.strip() if customer_uuid else None
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj

def delete_customer(db: Session, customer_id: int) -> bool:
    obj = db.get(Customer, customer_id)
    if not obj:
        return False
    db.delete(obj)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise
    return True

def get_customer_token(db: Session, customer_id: int) -> str | None:
    """
    Return the token/password to forward upstream.
    For now this returns the raw value stored in `secret_hash`.
    """
    obj = db.get(Customer, customer_id)
    if not obj:
        return None
    return obj.secret_hash

# -------------------
# Drafts
# -------------------

def get_draft(
    db: Session,
    *,
    user_id: int,
    customer_id: int,
    location_uuid: str,
) -> Draft | None:
    stmt = select(Draft).where(
        Draft.user_id == user_id,
        Draft.customer_id == customer_id,
        Draft.location_uuid == location_uuid,
    )
    return db.execute(stmt).scalar_one_or_none()

def upsert_draft(
    db: Session,
    *,
    user_id: int,
    customer_id: int,
    location_uuid: str,
    controllers: int,
    downstreams: int,
    grid_rows: list[dict],
) -> Draft:
    obj = get_draft(
        db,
        user_id=user_id,
        customer_id=customer_id,
        location_uuid=location_uuid,
    )
    grid_json = json.dumps(grid_rows)
    if obj:
        obj.controllers = controllers
        obj.downstreams = downstreams
        obj.grid_json = grid_json
    else:
        obj = Draft(
            user_id=user_id,
            customer_id=customer_id,
            location_uuid=location_uuid,
            controllers=controllers,
            downstreams=downstreams,
            grid_json=grid_json,
        )
        db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj

def delete_draft(
    db: Session,
    *,
    user_id: int,
    customer_id: int,
    location_uuid: str,
) -> bool:
    obj = get_draft(
        db,
        user_id=user_id,
        customer_id=customer_id,
        location_uuid=location_uuid,
    )
    if not obj:
        return False
    db.delete(obj)
    db.commit()
    return True
