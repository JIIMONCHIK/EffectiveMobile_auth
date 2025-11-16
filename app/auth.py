from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from app.config import settings
from app import models
from app.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(user: models.User, expires_delta: Optional[timedelta] = None):
    to_encode = {
        "user_id": user.id,
        "version": user.token_version
    }
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


def authenticate_user(db: Session, email: str, password: str):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user


from sqlalchemy.orm import joinedload

def get_current_user(
    credentials: str = Depends(security),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Auttainhenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(
            credentials.credentials, 
            settings.secret_key, 
            algorithms=[settings.algorithm]
        )
        user_id: int = payload.get("user_id")
        token_version: int = payload.get("version")
        
        if user_id is None or token_version is None:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    user = db.query(models.User).options(joinedload(models.User.role)).filter(models.User.id == user_id).first()
    
    if user is None or not user.is_active:
        raise credentials_exception
    
    # Проверяем версию токена
    if token_version != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


def check_permission(db: Session, user: models.User, element_name: str, permission: str):
    """Проверяет права доступа пользователя"""
    access_rule = db.query(models.AccessRule).join(models.Role).join(models.BusinessElement).filter(
        models.Role.id == user.role_id,
        models.BusinessElement.name == element_name
    ).first()
    
    if not access_rule:
        return False
    
    return getattr(access_rule, f"{permission}_permission", False)


