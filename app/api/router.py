from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean, Numeric
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime
from fastapi.responses import JSONResponse
import bcrypt
import asyncio
import os
from app.core.config import settings
from app.services.service_analysis import analyze_service_tasks

from fastapi import APIRouter
from typing import List, Optional

router = APIRouter()

# Database Configuration
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:mysql@localhost:3306/log_catalog"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    catalogs = relationship("Catalog", back_populates="user")

class Catalog(Base):
    __tablename__ = "catalogs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    catalog_name = Column(String(255), nullable=False)
    is_vertical = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="catalogs")
    subcatalogs = relationship("SubCatalog", back_populates="catalog")

class ServiceType(Base):
    __tablename__ = "service_types"
    id = Column(Integer, primary_key=True, index=True)
    service_type_name = Column(String(100), nullable=False, unique=True)
    kt_session = Column(String(10), nullable=False)
    fwd_shadow = Column(String(10), nullable=False)
    rev_shadow = Column(String(10), nullable=False)
    cutover = Column(String(10), nullable=False)
    
    # Relationship
    subcatalogs = relationship("SubCatalog", back_populates="service_type")

class SubCatalog(Base):
    __tablename__ = "subcatalogs"
    id = Column(Integer, primary_key=True, index=True)
    catalog_id = Column(Integer, ForeignKey('catalogs.id'), nullable=False)
    service_type_id = Column(Integer, ForeignKey('service_types.id'), nullable=False)
    sub_catalog_name = Column(String(255), nullable=False)
    service_level = Column(String(50), nullable=False)

    # Relationships
    catalog = relationship("Catalog", back_populates="subcatalogs")
    service_type = relationship("ServiceType", back_populates="subcatalogs")
    topics = relationship("Topic", back_populates="subcatalog")
    risks = relationship("SubCatalogRisk", back_populates="subcatalog")

class Topic(Base):
    __tablename__ = "topics"
    id = Column(Integer, primary_key=True, index=True)
    subcatalog_id = Column(Integer, ForeignKey('subcatalogs.id'), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(String(500), nullable=True)
    
    # Relationships
    subcatalog = relationship("SubCatalog", back_populates="topics")
    risks = relationship("TopicRisk", back_populates="topic")

class SubCatalogRisk(Base):
    __tablename__ = "subcatalog_risks"
    
    id = Column(Integer, primary_key=True, index=True)  # Unique primary key
    sub_catalog_id = Column(Integer, ForeignKey('subcatalogs.id'), nullable=False)
    risk = Column(String(500), nullable=True)
    status = Column(String(100), nullable=True)
    
    # Relationship
    subcatalog = relationship("SubCatalog", back_populates="risks")

class TopicRisk(Base):
    __tablename__ = "topic_risks"
    
    id = Column(Integer, primary_key=True, index=True)  # Unique primary key
    topic_id = Column(Integer, ForeignKey('topics.id'), nullable=False)
    risk = Column(String(500), nullable=True)
    status = Column(String(100), nullable=True)
    
    # Relationship
    topic = relationship("Topic", back_populates="risks")

# Create all tables
Base.metadata.create_all(bind=engine)

# Pydantic Models
class UserRegister(BaseModel):
    name: str
    email: str
    password: str
    confirmPassword: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True

class ServiceTypeCreate(BaseModel):
    service_type_name: str
    kt_session: str
    fwd_shadow: str
    rev_shadow: str
    cutover: str

class ServiceTypeResponse(BaseModel):
    id: int
    service_type_name: str
    kt_session: str
    fwd_shadow: str
    rev_shadow: str
    cutover: str

    class Config:
        from_attributes = True

class CatalogCreate(BaseModel):
    user_id: Optional[int] = None
    catalog_name: str
    is_vertical: bool = False

class CatalogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    catalog_name: str
    is_vertical: bool

    class Config:
        from_attributes = True

class SubCatalogCreate(BaseModel):
    catalog_id: int
    service_type_id: int
    sub_catalog_name: str
    service_level: str

class SubCatalogResponse(BaseModel):
    id: int
    catalog_id: int
    service_type_id: int
    sub_catalog_name: str
    service_level: str

    class Config:
        from_attributes = True

class TopicCreate(BaseModel):
    subcatalog_id: int
    name: str
    description: Optional[str] = None

class TopicResponse(BaseModel):
    id: int
    subcatalog_id: int
    name: str
    description: Optional[str]

    class Config:
        from_attributes = True

class SubCatalogRiskCreate(BaseModel):
    sub_catalog_id: int
    risk: Optional[str] = None
    status: Optional[str] = None

class SubCatalogRiskResponse(SubCatalogRiskCreate):
    id: int  
    class Config:
        from_attributes = True

class TopicRiskCreate(BaseModel):
    topic_id: int
    risk: Optional[str] = None
    status: Optional[str] = None

class TopicRiskResponse(TopicRiskCreate):
    id: int 
    class Config:
        from_attributes = True

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper functions
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )

async def init_catalog_and_data(db: Session):
    # Check if service types exist
    existing_service_types = db.query(ServiceType).first()
    if not existing_service_types:
 
        service_type_data = [
            {
                "service_type_name": "Governance",
                "kt_session": "30",
                "fwd_shadow": "30",
                "rev_shadow": "30",
                "cutover": "10"
            },
            {
                "service_type_name": "Incident",
                "kt_session": "30",
                "fwd_shadow": "30",
                "rev_shadow": "30",
                "cutover": "10"
            },
            {
                "service_type_name": "Maintenance",
                "kt_session": "30",
                "fwd_shadow": "30",
                "rev_shadow": "30",
                "cutover": "10"
            },
            {
                "service_type_name": "Monitoring",
                "kt_session": "30",
                "fwd_shadow": "30",
                "rev_shadow": "30",
                "cutover": "10"
            },
            {
                "service_type_name": "Operation Support",
                "kt_session": "30",
                "fwd_shadow": "30",
                "rev_shadow": "30",
                "cutover": "10"
            },
            {
                "service_type_name": "Production Support",
                "kt_session": "30",
                "fwd_shadow": "30",
                "rev_shadow": "30",
                "cutover": "10"
            },
            {
                "service_type_name": "Service Request",
                "kt_session": "30",
                "fwd_shadow": "30",
                "rev_shadow": "30",
                "cutover": "10"
            },
            {
                "service_type_name": "User Support",
                "kt_session": "30",
                "fwd_shadow": "30",
                "rev_shadow": "30",
                "cutover": "10"
            }
        ]

        # Add service types
        service_types_to_add = [ServiceType(**service_type) for service_type in service_type_data]
        db.add_all(service_types_to_add)
        db.commit()

# Startup event to initialize catalogs and subcatalogs
@router.on_event("startup")
async def startup():
    # Get a database session
    db = SessionLocal()
    try:
        await init_catalog_and_data(db)
    finally:
        db.close()
# User Routes

catalog_data = [
    {"catalog_name": "End-user Compute", "is_vertical": True, "user_id": 1},
    {"catalog_name": "Service Desk", "is_vertical": False, "user_id": 1},
    {"catalog_name": "Application Support", "is_vertical": True, "user_id": 1},
    {"catalog_name": "Maintenance Services", "is_vertical": True, "user_id": 1},
    {"catalog_name": "Security & Compliance", "is_vertical": True, "user_id": 1},
    {"catalog_name": "Cloud Services", "is_vertical": False, "user_id": 1},
    {"catalog_name": "Network Operations", "is_vertical": True, "user_id": 1},
    {"catalog_name": "Database Management", "is_vertical": False, "user_id": 1}
]

subcatalog_data = [
    {
        "catalog_id": 1,
        "sub_catalog_name": "Access/Privilege Issues",
        "service_level": "Level 1",
        "service_type_id": 8
    },
    {
        "catalog_id": 1,
        "sub_catalog_name": "Helpdesk, administration and Super Users",
        "service_level": "Level 1",
        "service_type_id": 8
    },
    {
        "catalog_id": 1,
        "sub_catalog_name": "Ad-hoc reports (Queries)",
        "service_level": "Level 2",
        "service_type_id": 8
    },
    {
        "catalog_id": 1,
        "sub_catalog_name": "Device Configuration Assistance",
        "service_level": "Level 1",
        "service_type_id": 8
    },
    {
        "catalog_id": 1,
        "sub_catalog_name": "Peripheral Device Setup & Troubleshooting",
        "service_level": "Level 1",
        "service_type_id": 8
    },
    {
        "catalog_id": 2,
        "sub_catalog_name": "Incident Management",
        "service_level": "Level 3",
        "service_type_id": 2
    },
    {
        "catalog_id": 2,
        "sub_catalog_name": "Service Request",
        "service_level": "Level 3",
        "service_type_id": 7
    },
    {
        "catalog_id": 2,
        "sub_catalog_name": "Functional & Hierarchical Escalation",
        "service_level": "Level 1",
        "service_type_id": 1
    },
    {
        "catalog_id": 2,
        "sub_catalog_name": "Monitoring Communications & Reporting",
        "service_level": "Level 1",
        "service_type_id": 1
    },
    {
        "catalog_id": 2,
        "sub_catalog_name": "First-line Technical Support",
        "service_level": "Level 1",
        "service_type_id": 2
    },
    {
        "catalog_id": 3,
        "sub_catalog_name": "Data Issues analysis & fix",
        "service_level": "Level 2",
        "service_type_id": 6
    },
    {
        "catalog_id": 3,
        "sub_catalog_name": "Break-fix of issues without changing application code",
        "service_level": "Level 2",
        "service_type_id": 6
    },
    {
        "catalog_id": 3,
        "sub_catalog_name": "Triage of Issues/tickets",
        "service_level": "Level 2",
        "service_type_id": 6
    },
    {
        "catalog_id": 3,
        "sub_catalog_name": "Issues analysis and hot fix (no code change)",
        "service_level": "Level 2",
        "service_type_id": 6
    },
    {
        "catalog_id": 3,
        "sub_catalog_name": "Application Configuration",
        "service_level": "Level 2",
        "service_type_id": 6
    },
    {
        "catalog_id": 3,
        "sub_catalog_name": "Application Performance Monitoring",
        "service_level": "Level 2",
        "service_type_id": 4
    },
    {
        "catalog_id": 3,
        "sub_catalog_name": "Error Log Analysis",
        "service_level": "Level 2",
        "service_type_id": 6
    },
    {
        "catalog_id": 4,
        "sub_catalog_name": "DB Maintenance, Archiving and Housekeeping",
        "service_level": "Level 2",
        "service_type_id": 3
    },
    {
        "catalog_id": 4,
        "sub_catalog_name": "Application Level Housekeeping activities",
        "service_level": "Level 2",
        "service_type_id": 3
    },
    {
        "catalog_id": 4,
        "sub_catalog_name": "Maintenance of workflows",
        "service_level": "Level 2",
        "service_type_id": 3
    },
    {
        "catalog_id": 4,
        "sub_catalog_name": "Upgrades, Patches, & Configuration Management",
        "service_level": "Level 2",
        "service_type_id": 5
    },
    {
        "catalog_id": 4,
        "sub_catalog_name": "Problem Management",
        "service_level": "Level 3",
        "service_type_id": 3
    },
    {
        "catalog_id": 4,
        "sub_catalog_name": "Change & Release Management",
        "service_level": "Level 3",
        "service_type_id": 3
    },
    {
        "catalog_id": 4,
        "sub_catalog_name": "Configuration Management",
        "service_level": "Level 3",
        "service_type_id": 3
    },
    {
        "catalog_id": 4,
        "sub_catalog_name": "System Health Check",
        "service_level": "Level 2",
        "service_type_id": 3
    },
    {
        "catalog_id": 5,
        "sub_catalog_name": "Security Incident Response",
        "service_level": "Level 3",
        "service_type_id": 2
    },
    {
        "catalog_id": 5,
        "sub_catalog_name": "Compliance Monitoring",
        "service_level": "Level 2",
        "service_type_id": 1
    },
    {
        "catalog_id": 5,
        "sub_catalog_name": "Vulnerability Assessment",
        "service_level": "Level 2",
        "service_type_id": 3
    },
    {
        "catalog_id": 6,
        "sub_catalog_name": "Cloud Infrastructure Monitoring",
        "service_level": "Level 2",
        "service_type_id": 4
    },
    {
        "catalog_id": 6,
        "sub_catalog_name": "Cloud Application Support",
        "service_level": "Level 2",
        "service_type_id": 6
    },
    {
        "catalog_id": 6,
        "sub_catalog_name": "Cloud Migration Assistance",
        "service_level": "Level 3",
        "service_type_id": 7
    },
    {
        "catalog_id": 7,
        "sub_catalog_name": "Network Health Monitoring",
        "service_level": "Level 2",
        "service_type_id": 4
    },
    {
        "catalog_id": 7,
        "sub_catalog_name": "Network Configuration",
        "service_level": "Level 2",
        "service_type_id": 3
    },
    {
        "catalog_id": 7,
        "sub_catalog_name": "Network Security Assessment",
        "service_level": "Level 3",
        "service_type_id": 1
    },
    {
        "catalog_id": 8,
        "sub_catalog_name": "Database Backup & Recovery",
        "service_level": "Level 2",
        "service_type_id": 3
    },
    {
        "catalog_id": 8,
        "sub_catalog_name": "Database Performance Tuning",
        "service_level": "Level 3",
        "service_type_id": 4
    }
]

###############
#intialize data
###############

@router.post("/users/{user_id}/add_catalog", response_model=List[CatalogResponse])
async def create_catalogs_for_user(
    user_id: int, 
    db: Session = Depends(get_db)
):
    # Validate user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prepare catalog objects
    catalog_objs = [
        Catalog(
            user_id=user_id, 
            catalog_name=catalog['catalog_name'],
            is_vertical=catalog['is_vertical']
        ) for catalog in catalog_data
    ]

    # Add and commit catalogs
    try:
        db.add_all(catalog_objs)
        db.commit()
        
        # Refresh to get generated IDs
        for catalog in catalog_objs:
            db.refresh(catalog)
        
        return catalog_objs
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Error creating catalogs: {str(e)}") 

@router.post("/users/add_subcatalog", response_model=List[SubCatalogResponse])
async def create_subcatalogs_for_catalog(
    db: Session = Depends(get_db)
):
    # Validate service types exist
    for subcatalog in subcatalog_data:
        service_type = db.query(ServiceType).filter(ServiceType.id == subcatalog['service_type_id']).first()
        if not service_type:
            raise HTTPException(status_code=404, detail=f"Service type {subcatalog['service_type_id']} not found")
    
    # Prepare subcatalog objects
    subcatalog_objs = [
        SubCatalog(
            catalog_id=subcatalog['catalog_id'],
            service_type_id=subcatalog['service_type_id'],
            sub_catalog_name=subcatalog['sub_catalog_name'],
            service_level=subcatalog['service_level']
        ) for subcatalog in subcatalog_data
    ]
    
    # Add and commit subcatalogs
    try:
        db.add_all(subcatalog_objs)
        db.commit()
       
        # Refresh to get generated IDs
        for subcatalog in subcatalog_objs:
            db.refresh(subcatalog)
       
        return subcatalog_objs
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Error creating subcatalogs: {str(e)}")

############
#USER ROUTES 
############

@router.post("/register", response_model=UserResponse)
async def register(user: UserRegister, db: Session = Depends(get_db)):
    # Validate passwords match
    if user.password != user.confirmPassword:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    
    # Check if email exists
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    hashed_password = hash_password(user.password)
    db_user = User(
        name=user.name,
        email=user.email,
        password=hashed_password
    )
    
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error")

@router.post("/login", response_model=UserResponse)
async def login(user: UserLogin, db: Session = Depends(get_db)):
    # Get user by email
    db_user = db.query(User).filter(User.email == user.email).first()
    
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return db_user

# User Details Route
@router.get("/user/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

#Catalog Routes
@router.get("/catalog/by-id/{catalog_id}", response_model=List[CatalogResponse])
async def get_catalog_by_id(catalog_id: int, db: Session = Depends(get_db)):
    catalogs = db.query(Catalog).filter(Catalog.id == catalog_id).all()
    
    if not catalogs:
        raise HTTPException(status_code=404, detail="No catalog found with the given ID")
    
    return catalogs

#####################
# Service Type Routes
#####################

@router.post("/service-type", response_model=ServiceTypeResponse)
async def create_service_type(service_type: ServiceTypeCreate, db: Session = Depends(get_db)):
    db_service_type = ServiceType(**service_type.dict())
    try:
        db.add(db_service_type)
        db.commit()
        db.refresh(db_service_type)
        return db_service_type
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating service type: {str(e)}")

@router.get("/service-types", response_model=List[ServiceTypeResponse])
async def get_all_service_types(db: Session = Depends(get_db)):
    service_types = db.query(ServiceType).all()
    if not service_types:
        raise HTTPException(status_code=404, detail="No service types found")
    return service_types

@router.get("/service-type/{service_type_id}", response_model=ServiceTypeResponse)
async def get_service_type(service_type_id: int, db: Session = Depends(get_db)):
    service_type = db.query(ServiceType).filter(ServiceType.id == service_type_id).first()
    if not service_type:
        raise HTTPException(status_code=404, detail="Service type not found")
    return service_type

@router.put("/service-type/user/{service_type_id}", response_model=ServiceTypeResponse)
async def update_service_type_name(
    service_type_id: int, 
    service_type: ServiceTypeCreate, 
    db: Session = Depends(get_db)
):
    db_service_type = db.query(ServiceType).filter(ServiceType.id == service_type_id).first()
    if not db_service_type:
        raise HTTPException(status_code=404, detail="Service type not found")
    
    try:
        # Only update service_type_name, ignore other fields
        db_service_type.service_type_name = service_type.service_type_name
        
        db.commit()
        db.refresh(db_service_type)
        return db_service_type
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating service type name: {str(e)}")

@router.put("/service-type/admin/{service_type_id}", response_model=ServiceTypeResponse)
async def update_service_type(service_type_id: int, service_type: ServiceTypeCreate, db: Session = Depends(get_db)):
    db_service_type = db.query(ServiceType).filter(ServiceType.id == service_type_id).first()
    if not db_service_type:
        raise HTTPException(status_code=404, detail="Service type not found")
    
    try:
        for key, value in service_type.dict().items():
            setattr(db_service_type, key, value)
        
        db.commit()
        db.refresh(db_service_type)
        return db_service_type
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating service type: {str(e)}")

@router.delete("/service-type/{service_type_id}")
async def delete_service_type(service_type_id: int, db: Session = Depends(get_db)):
    db_service_type = db.query(ServiceType).filter(ServiceType.id == service_type_id).first()
    if not db_service_type:
        raise HTTPException(status_code=404, detail="Service type not found")
    
    try:
        db.delete(db_service_type)
        db.commit()
        return {"detail": "Service type deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting service type: {str(e)}")

###############################
# Catalog Routes (with user_id)
###############################

@router.post("/user/catalog", response_model=CatalogResponse)
async def create_catalog(catalog: CatalogCreate, db: Session = Depends(get_db)):
    # Check if user exists
    user = db.query(User).filter(User.id == catalog.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_catalog = Catalog(**catalog.dict())
    try:
        db.add(db_catalog)
        db.commit()
        db.refresh(db_catalog)
        return db_catalog
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating catalog: {str(e)}")

@router.get("/user/{user_id}/catalogs", response_model=List[CatalogResponse])
async def get_user_catalogs(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    catalogs = db.query(Catalog).filter(Catalog.user_id == user_id).all()
    if not catalogs:
        raise HTTPException(status_code=404, detail="No catalogs found for this user")
    
    return catalogs

@router.get("/user/{user_id}/catalog/{catalog_id}", response_model=CatalogResponse)
async def get_specific_catalog(user_id: int, catalog_id: int, db: Session = Depends(get_db)):
    db_catalog = db.query(Catalog).filter(
        Catalog.id == catalog_id, 
        Catalog.user_id == user_id
    ).first()
    
    if not db_catalog:
        raise HTTPException(status_code=404, detail="Catalog not found")
    
    return db_catalog

@router.put("/user/{user_id}/catalog/{catalog_id}", response_model=CatalogResponse)
async def update_catalog(user_id: int, catalog_id: int, catalog: CatalogCreate, db: Session = Depends(get_db)):
    db_catalog = db.query(Catalog).filter(
        Catalog.id == catalog_id, 
        Catalog.user_id == user_id
    ).first()
    
    if not db_catalog:
        raise HTTPException(status_code=404, detail="Catalog not found")
    
    try:
        for key, value in catalog.dict().items():
            setattr(db_catalog, key, value)
        
        db.commit()
        db.refresh(db_catalog)
        return db_catalog
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating catalog: {str(e)}")

@router.delete("/user/{user_id}/catalog/{catalog_id}")
async def delete_catalog(user_id: int, catalog_id: int, db: Session = Depends(get_db)):
    db_catalog = db.query(Catalog).filter(
        Catalog.id == catalog_id, 
        Catalog.user_id == user_id
    ).first()
    
    if not db_catalog:
        raise HTTPException(status_code=404, detail="Catalog not found")
    
    try:
        db.delete(db_catalog)
        db.commit()
        return {"detail": "Catalog deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting catalog: {str(e)}")

#####################################
# SubCatalog Routes (with catalog_id)
#####################################

@router.post("/subcatalog", response_model=SubCatalogResponse)
async def create_subcatalog(subcatalog: SubCatalogCreate, db: Session = Depends(get_db)):
    # Check if catalog exists
    catalog = db.query(Catalog).filter(Catalog.id == subcatalog.catalog_id).first()
    if not catalog:
        raise HTTPException(status_code=404, detail="Catalog not found")
    
    # Check if service type exists
    service_type = db.query(ServiceType).filter(ServiceType.id == subcatalog.service_type_id).first()
    if not service_type:
        raise HTTPException(status_code=404, detail="Service type not found")
    
    db_subcatalog = SubCatalog(**subcatalog.dict())
    try:
        db.add(db_subcatalog)
        db.commit()
        db.refresh(db_subcatalog)
        return db_subcatalog
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating subcatalog: {str(e)}")

@router.get("/catalog/{catalog_id}/subcatalogs", response_model=List[SubCatalogResponse])
async def get_catalog_subcatalogs(catalog_id: int, db: Session = Depends(get_db)):
    catalog = db.query(Catalog).filter(Catalog.id == catalog_id).first()
    if not catalog:
        raise HTTPException(status_code=404, detail="Catalog not found")
    
    subcatalogs = db.query(SubCatalog).filter(SubCatalog.catalog_id == catalog_id).all()
    if not subcatalogs:
        raise HTTPException(status_code=404, detail="No subcatalogs found for this catalog")
    
    return subcatalogs

@router.get("/catalog/{catalog_id}/subcatalog/{subcatalog_id}", response_model=SubCatalogResponse)
async def get_specific_subcatalog(catalog_id: int, subcatalog_id: int, db: Session = Depends(get_db)):
    db_subcatalog = db.query(SubCatalog).filter(
        SubCatalog.id == subcatalog_id, 
        SubCatalog.catalog_id == catalog_id
    ).first()
    
    if not db_subcatalog:
        raise HTTPException(status_code=404, detail="Subcatalog not found")
    
    return db_subcatalog

@router.put("/catalog/{catalog_id}/subcatalog/{subcatalog_id}", response_model=SubCatalogResponse)
async def update_subcatalog(catalog_id: int, subcatalog_id: int, subcatalog: SubCatalogCreate, db: Session = Depends(get_db)):
    db_subcatalog = db.query(SubCatalog).filter(
        SubCatalog.id == subcatalog_id, 
        SubCatalog.catalog_id == catalog_id
    ).first()
    
    if not db_subcatalog:
        raise HTTPException(status_code=404, detail="Subcatalog not found")
    
    try:
        for key, value in subcatalog.dict().items():
            setattr(db_subcatalog, key, value)
        
        db.commit()
        db.refresh(db_subcatalog)
        return db_subcatalog
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating subcatalog: {str(e)}")

@router.delete("/catalog/{catalog_id}/subcatalog/{subcatalog_id}")
async def delete_subcatalog(catalog_id: int, subcatalog_id: int, db: Session = Depends(get_db)):
    db_subcatalog = db.query(SubCatalog).filter(
        SubCatalog.id == subcatalog_id, 
        SubCatalog.catalog_id == catalog_id
    ).first()
    
    if not db_subcatalog:
        raise HTTPException(status_code=404, detail="Subcatalog not found")
    
    try:
        db.delete(db_subcatalog)
        db.commit()
        return {"detail": "Subcatalog deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting subcatalog: {str(e)}")

##################################
# Topic Routes (with subcatalog_id)
##################################

@router.post("/topic", response_model=TopicResponse)
async def create_topic(topic: TopicCreate, db: Session = Depends(get_db)):
    # Check if subcatalog exists
    subcatalog = db.query(SubCatalog).filter(SubCatalog.id == topic.subcatalog_id).first()
    if not subcatalog:
        raise HTTPException(status_code=404, detail="Subcatalog not found")
   
    db_topic = Topic(**topic.dict())
    try:
        db.add(db_topic)
        db.commit()
        db.refresh(db_topic)
        return db_topic
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating topic: {str(e)}")

@router.get("/subcatalog/{subcatalog_id}/topics", response_model=List[TopicResponse])
async def get_subcatalog_topics(subcatalog_id: int, db: Session = Depends(get_db)):
    subcatalog = db.query(SubCatalog).filter(SubCatalog.id == subcatalog_id).first()
    if not subcatalog:
        raise HTTPException(status_code=404, detail="Subcatalog not found")
    
    topics = db.query(Topic).filter(Topic.subcatalog_id == subcatalog_id).all()
    if not topics:
        raise HTTPException(status_code=404, detail="No topics found for this subcatalog")
    
    return topics

@router.get("/subcatalog/{subcatalog_id}/topic/{topic_id}", response_model=TopicResponse)
async def get_specific_topic(subcatalog_id: int, topic_id: int, db: Session = Depends(get_db)):
    db_topic = db.query(Topic).filter(
        Topic.id == topic_id, 
        Topic.subcatalog_id == subcatalog_id
    ).first()
    
    if not db_topic:
        raise HTTPException(status_code=404, detail="Topic not found")
    
    return db_topic

@router.put("/subcatalog/{subcatalog_id}/topic/{topic_id}", response_model=TopicResponse)
async def update_topic(subcatalog_id: int, topic_id: int, topic: TopicCreate, db: Session = Depends(get_db)):
    db_topic = db.query(Topic).filter(
        Topic.id == topic_id, 
        Topic.subcatalog_id == subcatalog_id
    ).first()
    
    if not db_topic:
        raise HTTPException(status_code=404, detail="Topic not found")
    
    try:
        for key, value in topic.dict().items():
            setattr(db_topic, key, value)
        
        db.commit()
        db.refresh(db_topic)
        return db_topic
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating topic: {str(e)}")

@router.delete("/subcatalog/{subcatalog_id}/topic/{topic_id}")
async def delete_topic(subcatalog_id: int, topic_id: int, db: Session = Depends(get_db)):
    db_topic = db.query(Topic).filter(
        Topic.id == topic_id, 
        Topic.subcatalog_id == subcatalog_id
    ).first()
    
    if not db_topic:
        raise HTTPException(status_code=404, detail="Topic not found")
    
    try:
        db.delete(db_topic)
        db.commit()
        return {"detail": "Topic deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting topic: {str(e)}")

########################
# SUBCATALOG RISK ROUTES
########################
@router.post("/subcatalog-risks/", response_model=SubCatalogRiskResponse)
def create_subcatalog_risk(
    subcatalog_risk: SubCatalogRiskCreate, 
    db: Session = Depends(get_db)
):
    # Check if subcatalog exists
    existing_subcatalog = db.query(SubCatalog).filter(SubCatalog.id == subcatalog_risk.sub_catalog_id).first()
    if not existing_subcatalog:
        raise HTTPException(status_code=404, detail="Subcatalog not found")
    
    # Create new subcatalog risk
    db_subcatalog_risk = SubCatalogRisk(**subcatalog_risk.dict())
    db.add(db_subcatalog_risk)
    db.commit()
    db.refresh(db_subcatalog_risk)
    return db_subcatalog_risk

@router.get("/subcatalog-risks/", response_model=List[SubCatalogRiskResponse])
def read_subcatalog_risks(db: Session = Depends(get_db)):
    subcatalog_risks = db.query(SubCatalogRisk).all()
    return subcatalog_risks

@router.get("/subcatalog-risks/{risk_id}", response_model=SubCatalogRiskResponse)
def read_subcatalog_risk(
    risk_id: int, 
    db: Session = Depends(get_db)
):
    subcatalog_risk = db.query(SubCatalogRisk).filter(SubCatalogRisk.id == risk_id).first()
    if not subcatalog_risk:
        raise HTTPException(status_code=404, detail="Subcatalog risk not found")
    return subcatalog_risk

@router.get("/subcatalog-risks/by-subcatalog/{sub_catalog_id}", response_model=List[SubCatalogRiskResponse])
def read_subcatalog_risks_by_subcatalog(
    sub_catalog_id: int, 
    db: Session = Depends(get_db)
):
    subcatalog_risks = db.query(SubCatalogRisk).filter(SubCatalogRisk.sub_catalog_id == sub_catalog_id).all()
    return subcatalog_risks

@router.put("/subcatalog-risks/{risk_id}", response_model=SubCatalogRiskResponse)
def update_subcatalog_risk(
    risk_id: int, 
    subcatalog_risk: SubCatalogRiskCreate, 
    db: Session = Depends(get_db)
):
    # Find existing risk
    db_subcatalog_risk = db.query(SubCatalogRisk).filter(SubCatalogRisk.id == risk_id).first()
    if not db_subcatalog_risk:
        raise HTTPException(status_code=404, detail="Subcatalog risk not found")
    
    # Update fields
    for key, value in subcatalog_risk.dict().items():
        setattr(db_subcatalog_risk, key, value)
    
    db.commit()
    db.refresh(db_subcatalog_risk)
    return db_subcatalog_risk

@router.delete("/subcatalog-risks/{risk_id}")
def delete_subcatalog_risk(
    risk_id: int, 
    db: Session = Depends(get_db)
):
    # Find existing risk
    db_subcatalog_risk = db.query(SubCatalogRisk).filter(SubCatalogRisk.id == risk_id).first()
    if not db_subcatalog_risk:
        raise HTTPException(status_code=404, detail="Subcatalog risk not found")
    
    db.delete(db_subcatalog_risk)
    db.commit()
    return {"detail": "Subcatalog risk deleted successfully"}
###################
# TOPIC RISK ROUTES
###################

@router.post("/topic-risks/", response_model=TopicRiskResponse)
def create_topic_risk(
    topic_risk: TopicRiskCreate, 
    db: Session = Depends(get_db)
):
    # Check if topic exists
    existing_topic = db.query(Topic).filter(Topic.id == topic_risk.topic_id).first()
    if not existing_topic:
        raise HTTPException(status_code=404, detail="Topic not found")
    
    # Create new topic risk
    db_topic_risk = TopicRisk(**topic_risk.dict())
    db.add(db_topic_risk)
    db.commit()
    db.refresh(db_topic_risk)
    return db_topic_risk

@router.get("/topic-risks/", response_model=List[TopicRiskResponse])
def read_topic_risks(db: Session = Depends(get_db)):
    topic_risks = db.query(TopicRisk).all()
    return topic_risks

@router.get("/topic-risks/{risk_id}", response_model=TopicRiskResponse)
def read_topic_risk(
    risk_id: int, 
    db: Session = Depends(get_db)
):
    topic_risk = db.query(TopicRisk).filter(TopicRisk.id == risk_id).first()
    if not topic_risk:
        raise HTTPException(status_code=404, detail="Topic risk not found")
    return topic_risk

@router.get("/topic-risks/by-topic/{topic_id}", response_model=List[TopicRiskResponse])
def read_topic_risks_by_topic(
    topic_id: int, 
    db: Session = Depends(get_db)
):
    topic_risks = db.query(TopicRisk).filter(TopicRisk.topic_id == topic_id).all()
    return topic_risks

@router.put("/topic-risks/{risk_id}", response_model=TopicRiskResponse)
def update_topic_risk(
    risk_id: int, 
    topic_risk: TopicRiskCreate, 
    db: Session = Depends(get_db)
):
    # Find existing risk
    db_topic_risk = db.query(TopicRisk).filter(TopicRisk.id == risk_id).first()
    if not db_topic_risk:
        raise HTTPException(status_code=404, detail="Topic risk not found")
    
    # Update fields
    for key, value in topic_risk.dict().items():
        setattr(db_topic_risk, key, value)
    
    db.commit()
    db.refresh(db_topic_risk)
    return db_topic_risk

@router.delete("/topic-risks/{risk_id}")
def delete_topic_risk(
    risk_id: int, 
    db: Session = Depends(get_db)
):
    # Find existing risk
    db_topic_risk = db.query(TopicRisk).filter(TopicRisk.id == risk_id).first()
    if not db_topic_risk:
        raise HTTPException(status_code=404, detail="Topic risk not found")
    
    db.delete(db_topic_risk)
    db.commit()
    return {"detail": "Topic risk deleted successfully"}