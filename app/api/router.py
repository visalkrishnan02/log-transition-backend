from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
import bcrypt

from fastapi import APIRouter
from typing import List

router = APIRouter()

SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:mysql@localhost:3306/log_project_users"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# SAMPLE_SERVICES data
SAMPLE_SERVICES = [
    {
        "Service_Offerings_Major": "Alert & Monitoring Job",
        "Service_Type": "Monitoring",
        "Service_Level": "Level 1"
    },
    {
        "Service_Offerings_Major": "Application and Batch Job Monitoring",
        "Service_Type": "Monitoring",
        "Service_Level": "Level 1"
    },
    {
        "Service_Offerings_Major": "Application & Batch Job Daily Health Check",
        "Service_Type": "Monitoring",
        "Service_Level": "Level 1"
    },
    {
        "Service_Offerings_Major": "Monitoring Communications & Reporting",
        "Service_Type": "Governance",
        "Service_Level": "Level 1"
    },
    {
        "Service_Offerings_Major": "Functional & Hierarchical Escalation",
        "Service_Type": "Governance",
        "Service_Level": "Level 1"
    },
    {
        "Service_Offerings_Major": "Access/Privilege Issues",
        "Service_Type": "User Support",
        "Service_Level": "Level 1"
    },
    {
        "Service_Offerings_Major": "Helpdesk, administration and Super Users",
        "Service_Type": "User Support",
        "Service_Level": "Level 1"
    },
    {
        "Service_Offerings_Major": "Data Issues analysis & fix",
        "Service_Type": "Production Support",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Break-fix of issues without changing application code",
        "Service_Type": "Production Support",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Triage of Issues/tickets",
        "Service_Type": "Production Support",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Issues analysis and hot fix (no code change)",
        "Service_Type": "Production Support",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Application Configuration",
        "Service_Type": "Production Support",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Ad-hoc reports (Queries)",
        "Service_Type": "User Support",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Upgrades, Patches, & configuration management",
        "Service_Type": "Operation Support",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "DB Maintenance, Archiving and Housekeeping",
        "Service_Type": "Maintenance",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Application Level Housekeeping activities",
        "Service_Type": "Maintenance",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Maintenance of workflows",
        "Service_Type": "Maintenance",
        "Service_Level": "Level 2"
    },
    {
        "Service_Offerings_Major": "Incident Management",
        "Service_Type": "Incident",
        "Service_Level": "Level 3"
    },
    {
        "Service_Offerings_Major": "Problem Management",
        "Service_Type": "Maintenance",
        "Service_Level": "Level 3"
    },
    {
        "Service_Offerings_Major": "Change & Release Management",
        "Service_Type": "Maintenance",
        "Service_Level": "Level 3"
    },
    {
        "Service_Offerings_Major": "Configuration Management",
        "Service_Type": "Maintenance",
        "Service_Level": "Level 3"
    },
    {
        "Service_Offerings_Major": "Service Request",
        "Service_Type": "Service Request",
        "Service_Level": "Level 3"
    },
    {
        "Service_Offerings_Major": "Minor Enhancement less than 40 hours",
        "Service_Type": "Enhancement",
        "Service_Level": "Level 3"
    },
    {
        "Service_Offerings_Major": "Major Enhancement range from 40 to 100 hours",
        "Service_Type": "Enhancement",
        "Service_Level": "Level 3"
    },
    {
        "Service_Offerings_Major": "Service Improvement",
        "Service_Type": "Service Improvement",
        "Service_Level": "Level 3"
    }
]


# Database Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Service(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    Service_Offerings_Major = Column(String(255), nullable=False)
    Service_Level = Column(String(50), nullable=False)
    Service_Type = Column(String(100), nullable=False)

# Create all tables
Base.metadata.create_all(bind=engine)

# Pydantic Models for request/response
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

class ServiceResponse(BaseModel):
    id: int
    Service_Offerings_Major: str
    Service_Level: str
    Service_Type: str

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

# Function to initialize services
def init_services(db: Session):
    # Check if services already exist
    existing_services = db.query(Service).first()
    if existing_services:
        return
    
    # Add services from the SAMPLE_SERVICES list
    services_to_add = [
        Service(
            Service_Offerings_Major=service['Service_Offerings_Major'],
            Service_Level=service['Service_Level'],
            Service_Type=service['Service_Type']
        ) for service in SAMPLE_SERVICES
    ]
    
    db.add_all(services_to_add)
    db.commit()

# Startup event to initialize services
@router.on_event("startup")
async def startup():
    # Get a database session
    db = SessionLocal()
    try:
        init_services(db)
    finally:
        db.close()

# User Routes
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

# Services Routes
@router.get("/services", response_model=List[ServiceResponse])
async def get_all_services(db: Session = Depends(get_db)):
    services = db.query(Service).all()
    return services

@router.get("/services/by-type/{service_type}", response_model=List[ServiceResponse])
async def get_services_by_type(service_type: str, db: Session = Depends(get_db)):
    services = db.query(Service).filter(Service.Service_Type == service_type).all()
    if not services:
        raise HTTPException(status_code=404, detail="No services found for this type")
    return services

@router.get("/services/by-level/{service_level}", response_model=List[ServiceResponse])
async def get_services_by_level(service_level: str, db: Session = Depends(get_db)):
    services = db.query(Service).filter(Service.Service_Level == service_level).all()
    if not services:
        raise HTTPException(status_code=404, detail="No services found for this level")
    return services