# app/models.py
from sqlalchemy.orm import Mapped, mapped_column  # type: ignore
from sqlalchemy import String, Integer, DateTime, func, UniqueConstraint, ForeignKey  # type: ignore
from app.database import Base

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("email", name="uq_users_email"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    username: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)  # 320 = RFC max
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class Customer(Base):
    __tablename__ = "customers"
    __table_args__ = (UniqueConstraint("name", name="uq_customers_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # "credentials" or "token"
    auth_method: Mapped[str] = mapped_column(String(20), nullable=False)

    # only used when auth_method == "credentials"
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # NOTE: For now we store the *raw* token/password here (no hashing) as requested.
    # Column name stays "secret_hash" to avoid a DB migration at this moment.
    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # external/customer UUID supplied by UI (optional at DB level but required by UI)
    customer_uuid: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    # ownership
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    # optional (unused right now); keep nullable so ORM can select it without errors
    token_ciphertext: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
