from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from contextlib import asynccontextmanager

from app import models, schemas, auth
from app.database import SessionLocal, engine, get_db
from app.auth import get_current_user, check_permission


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Создаем таблицы в БД
    models.Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Создаем базовые роли
        roles_data = [
            {"name": "admin", "description": "Administrator with full access"},
            {"name": "manager", "description": "Manager with extended permissions"},
            {"name": "user", "description": "Regular user"}
        ]
        
        for role_data in roles_data:
            role = db.query(models.Role).filter(models.Role.name == role_data["name"]).first()
            if not role:
                db.add(models.Role(**role_data))
        
        db.commit()
        
        # Создаем бизнес-элементы
        elements_data = [
            {"name": "users", "description": "User management"},
            {"name": "products", "description": "Product management"},
            {"name": "orders", "description": "Order management"},
            {"name": "access_rules", "description": "Access rules management"}
        ]
        
        for element_data in elements_data:
            element = db.query(models.BusinessElement).filter(models.BusinessElement.name == element_data["name"]).first()
            if not element:
                db.add(models.BusinessElement(**element_data))
        
        db.commit()
        
        # Настраиваем права для админа (все разрешено)
        admin_role = db.query(models.Role).filter(models.Role.name == "admin").first()
        if admin_role:
            for element in db.query(models.BusinessElement).all():
                existing_rule = db.query(models.AccessRule).filter(
                    models.AccessRule.role_id == admin_role.id,
                    models.AccessRule.element_id == element.id
                ).first()
                
                if not existing_rule:
                    access_rule = models.AccessRule(
                        role_id=admin_role.id,
                        element_id=element.id,
                        read_permission=True,
                        read_all_permission=True,
                        create_permission=True,
                        update_permission=True,
                        update_all_permission=True,
                        delete_permission=True,
                        delete_all_permission=True
                    )
                    db.add(access_rule)
        
        db.commit()
        
        # Настраиваем базовые права для менеджера
        manager_role = db.query(models.Role).filter(models.Role.name == "manager").first()
        if manager_role:
            for element in db.query(models.BusinessElement).all():
                existing_rule = db.query(models.AccessRule).filter(
                    models.AccessRule.role_id == manager_role.id,
                    models.AccessRule.element_id == element.id
                ).first()
                
                if not existing_rule:
                    # Менеджер имеет расширенные права, но не все как админ
                    access_rule = models.AccessRule(
                        role_id=manager_role.id,
                        element_id=element.id,
                        read_permission=True,
                        read_all_permission=True,  # Может читать все
                        create_permission=True,
                        update_permission=True,
                        update_all_permission=True,  # Может обновлять все
                        delete_permission=False,     # Не может удалять
                        delete_all_permission=False
                    )

                    if element.name == "users":
                        access_rule.delete_permission = False
                        access_rule.delete_all_permission = False
                    db.add(access_rule)
        
        db.commit()
        
        # Настраиваем базовые права для обычного пользователя
        user_role = db.query(models.Role).filter(models.Role.name == "user").first()
        if user_role:
            # Права на работу со своим профилем
            users_element = db.query(models.BusinessElement).filter(models.BusinessElement.name == "users").first()
            if users_element:
                existing_rule = db.query(models.AccessRule).filter(
                    models.AccessRule.role_id == user_role.id,
                    models.AccessRule.element_id == users_element.id
                ).first()
                
                if not existing_rule:
                    access_rule = models.AccessRule(
                        role_id=user_role.id,
                        element_id=users_element.id,
                        read_permission=True,       # Может читать свой профиль
                        read_all_permission=False,  # Не может читать чужие профили
                        create_permission=True,     # Может создавать аккаунт (регистрироваться)
                        update_permission=True,     # Может обновлять свой профиль
                        update_all_permission=False, # Не может обновлять чужие профили
                        delete_permission=True,     # Может удалить свой аккаунт
                        delete_all_permission=False # Не может удалять чужие аккаунты
                    )
                    db.add(access_rule)
            
            # Права на просмотр продуктов
            products_element = db.query(models.BusinessElement).filter(models.BusinessElement.name == "products").first()
            if products_element:
                existing_rule = db.query(models.AccessRule).filter(
                    models.AccessRule.role_id == user_role.id,
                    models.AccessRule.element_id == products_element.id
                ).first()
                
                if not existing_rule:
                    access_rule = models.AccessRule(
                        role_id=user_role.id,
                        element_id=products_element.id,
                        read_permission=True,
                        read_all_permission=True,
                        create_permission=False,
                        update_permission=False,
                        update_all_permission=False,
                        delete_permission=False,
                        delete_all_permission=False
                    )
                    db.add(access_rule)
            
            # Права на работу с заказами
            orders_element = db.query(models.BusinessElement).filter(models.BusinessElement.name == "orders").first()
            if orders_element:
                existing_rule = db.query(models.AccessRule).filter(
                    models.AccessRule.role_id == user_role.id,
                    models.AccessRule.element_id == orders_element.id
                ).first()
                
                if not existing_rule:
                    access_rule = models.AccessRule(
                        role_id=user_role.id,
                        element_id=orders_element.id,
                        read_permission=True,
                        read_all_permission=False,
                        create_permission=True,
                        update_permission=True,
                        update_all_permission=False,
                        delete_permission=True,
                        delete_all_permission=False
                    )
                    db.add(access_rule)
            
            # Нет прав на управление access_rules
            access_rules_element = db.query(models.BusinessElement).filter(models.BusinessElement.name == "access_rules").first()
            if access_rules_element:
                existing_rule = db.query(models.AccessRule).filter(
                    models.AccessRule.role_id == user_role.id,
                    models.AccessRule.element_id == access_rules_element.id
                ).first()
                
                if not existing_rule:
                    access_rule = models.AccessRule(
                        role_id=user_role.id,
                        element_id=access_rules_element.id,
                        read_permission=False,
                        read_all_permission=False,
                        create_permission=False,
                        update_permission=False,
                        update_all_permission=False,
                        delete_permission=False,
                        delete_all_permission=False
                    )
                    db.add(access_rule)
        
        db.commit()
        
        # Создаем админа
        admin_email = "admin@example.com"
        admin_user = db.query(models.User).filter(models.User.email == admin_email).first()
        
        if not admin_user and admin_role:
            hashed_password = auth.get_password_hash("admin123")
            admin_user = models.User(
                email=admin_email,
                password_hash=hashed_password,
                first_name="Admin",
                last_name="User",
                role_id=admin_role.id
            )
            db.add(admin_user)
            print("Admin user created: admin@example.com / admin123")
        
        # Создаем менеджера
        manager_email = "manager@example.com"
        manager_user = db.query(models.User).filter(models.User.email == manager_email).first()
        
        if not manager_user and manager_role:
            hashed_password = auth.get_password_hash("manager123")
            manager_user = models.User(
                email=manager_email,
                password_hash=hashed_password,
                first_name="Manager",
                last_name="User", 
                role_id=manager_role.id
            )
            db.add(manager_user)
            print("Manager user created: manager@example.com / manager123")
        
        # Создаем обычного пользователя
        user_email = "user@example.com"
        regular_user = db.query(models.User).filter(models.User.email == user_email).first()
        
        if not regular_user and user_role:
            hashed_password = auth.get_password_hash("user123")
            regular_user = models.User(
                email=user_email,
                password_hash=hashed_password,
                first_name="Regular",
                last_name="User",
                role_id=user_role.id
            )
            db.add(regular_user)
            print("Regular user created: user@example.com / user123")
        
        db.commit()
        print("Начальные данные успешно созданы")
        
    except Exception as e:
        print(f"Ошибка при инициализации: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()
    
    yield
    print("Приложение завершает работу")


app = FastAPI(title="Authentication System", version="1.0.0", lifespan=lifespan)


# Вспомогательная функция для проверки прав
def require_permission(element_name: str, permission: str):
    def permission_dependency(
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        if not check_permission(db, current_user, element_name, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return permission_dependency

# Регистрация пользователя
@app.post("/register", response_model=schemas.UserInDB)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if user.password != user.password_repeat:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match"
        )
    
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Назначаем роль по умолчанию (обычный пользователь)
    default_role = db.query(models.Role).filter(models.Role.name == "user").first()
    if not default_role:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default role not found"
        )
    
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        password_hash=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
        middle_name=user.middle_name,
        role_id=default_role.id
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Логин
@app.post("/login", response_model=schemas.Token)
def login(
    user_data: schemas.UserLogin,
    db: Session = Depends(get_db)
):
    user = auth.authenticate_user(db, user_data.email, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = auth.create_access_token(user=user)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/logout")
def logout(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.token_version += 1
    db.commit()
    return {"message": "Successfully logged out. All tokens revoked."}

# Получить текущего пользователя (требует права на чтение пользователей)
@app.get("/users/me", response_model=schemas.UserInDB)
def read_users_me(current_user: models.User = Depends(require_permission("users", "read"))):
    return current_user

# Обновление пользователя (требует права на обновление пользователей)
@app.put("/users/me", response_model=schemas.UserInDB)
def update_user_me(
    user_update: schemas.UserUpdate,
    current_user: models.User = Depends(require_permission("users", "update")),
    db: Session = Depends(get_db)
):
    # Проверяем, не занят ли email другим пользователем
    if user_update.email and user_update.email != current_user.email:
        existing_user = db.query(models.User).filter(
            models.User.email == user_update.email,
            models.User.id != current_user.id  # Исключаем текущего пользователя
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered by another user"
            )

    # Обновляем только переданные поля
    update_data = user_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(current_user, field, value)
    
    db.commit()
    db.refresh(current_user)
    return current_user

# Удаление пользователя (требует права на удаление пользователей)
@app.delete("/users/me")
def delete_user_me(
    current_user: models.User = Depends(require_permission("users", "delete")),
    db: Session = Depends(get_db)
):
    current_user.is_active = False
    current_user.token_version += 1  # Инвалидируем все токены
    db.commit()
    return {"message": "User deactivated successfully"}

# Mock эндпоинты для бизнес-объектов
@app.get("/products")
def get_products(current_user: models.User = Depends(require_permission("products", "read"))):
    return {"products": ["Product 1", "Product 2", "Product 3"]}

@app.post("/products")
def create_product(current_user: models.User = Depends(require_permission("products", "create"))):
    return {"message": "Product created", "product": "New Product"}

@app.put("/products/{product_id}")
def update_product(
    product_id: int,
    current_user: models.User = Depends(require_permission("products", "update"))
):
    return {"message": f"Product {product_id} updated"}

@app.delete("/products/{product_id}")
def delete_product(
    product_id: int,
    current_user: models.User = Depends(require_permission("products", "delete"))
):
    return {"message": f"Product {product_id} deleted"}

@app.get("/orders")
def get_orders(current_user: models.User = Depends(require_permission("orders", "read"))):
    return {"orders": ["Order 1", "Order 2", "Order 3"]}

# Админские эндпоинты для управления правами
@app.get("/admin/users", response_model=List[schemas.UserInDB])
def get_all_users(
    current_user: models.User = Depends(require_permission("users", "read_all")),
    db: Session = Depends(get_db)
):
    return db.query(models.User).all()

@app.get("/admin/access-rules", response_model=List[schemas.AccessRuleInDB])
def get_access_rules(
    current_user: models.User = Depends(require_permission("access_rules", "read")),
    db: Session = Depends(get_db)
):
    return db.query(models.AccessRule).all()

@app.put("/admin/access-rules/{rule_id}", response_model=schemas.AccessRuleInDB)
def update_access_rule(
    rule_id: int,
    rule_update: schemas.AccessRuleBase,
    current_user: models.User = Depends(require_permission("access_rules", "update")),
    db: Session = Depends(get_db)
):
    rule = db.query(models.AccessRule).filter(models.AccessRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Access rule not found")
    
    for field, value in rule_update.dict(exclude_unset=True).items():
        setattr(rule, field, value)
    
    db.commit()
    db.refresh(rule)
    return rule

# Health check
@app.get("/")
def read_root():
    return {"message": "Authentication System API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}