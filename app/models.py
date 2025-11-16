from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    first_name = Column(String)
    last_name = Column(String)
    middle_name = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    token_version = Column(Integer, default=0)
    
    # Связи
    role_id = Column(Integer, ForeignKey("roles.id"))
    role = relationship("Role", back_populates="users")


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)
    
    users = relationship("User", back_populates="role")
    access_rules = relationship("AccessRule", back_populates="role")


class BusinessElement(Base):
    __tablename__ = "business_elements"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)

    access_rules = relationship("AccessRule", back_populates="element")


class AccessRule(Base):
    __tablename__ = "access_rules"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"))
    element_id = Column(Integer, ForeignKey("business_elements.id"))
    
    read_permission = Column(Boolean, default=False)
    read_all_permission = Column(Boolean, default=False)
    create_permission = Column(Boolean, default=False)
    update_permission = Column(Boolean, default=False)
    update_all_permission = Column(Boolean, default=False)
    delete_permission = Column(Boolean, default=False)
    delete_all_permission = Column(Boolean, default=False)

    role = relationship("Role", back_populates="access_rules")
    element = relationship("BusinessElement", back_populates="access_rules")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    session_token = Column(String, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())