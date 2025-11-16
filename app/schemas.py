from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    middle_name: Optional[str] = None


class UserCreate(UserBase):
    password: str
    password_repeat: str


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    middle_name: Optional[str] = None


class UserInDB(UserBase):
    id: int
    is_active: bool
    role_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_id: Optional[int] = None


class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None


class RoleInDB(RoleBase):
    id: int

    class Config:
        from_attributes = True


class AccessRuleBase(BaseModel):
    role_id: int
    element_id: int
    read_permission: bool = False
    read_all_permission: bool = False
    create_permission: bool = False
    update_permission: bool = False
    update_all_permission: bool = False
    delete_permission: bool = False
    delete_all_permission: bool = False


class AccessRuleInDB(AccessRuleBase):
    id: int

    class Config:
        from_attributes = True