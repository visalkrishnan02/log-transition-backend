from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime
from fastapi.responses import JSONResponse
import bcrypt
import asyncio

from fastapi import APIRouter
from typing import List, Optional

from app.services.service_analysis import analyze_service_tasks
from app.services.timeline_generation import timeline_generation
from app.services.openai_call import azure_openai_call
from app.core.config import settings

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

TEMPLATE_TIMELINE_DATA = [
    {
        "Service_Type": "Monitoring",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Monitoring",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Monitoring",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Monitoring",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "Governance",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Governance",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Governance",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Governance",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "User Support",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "User Support",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "User Support",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "User Support",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "Production Support",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Production Support",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Production Support",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Production Support",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "Operation Support",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Operation Support",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Operation Support",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Operation Support",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "Maintenance",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Maintenance",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Maintenance",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Maintenance",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "Incident",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Incident",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Incident",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Incident",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "Service Request",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Service Request",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Service Request",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Service Request",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "Enhancement",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Enhancement",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Enhancement",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Enhancement",
        "Event_Type": "Cutover",
        "Timeline": ""
    },
    {
        "Service_Type": "Service Improvement",
        "Event_Type": "KT Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Service Improvement",
        "Event_Type": "Fwd Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Service Improvement",
        "Event_Type": "Rev Session",
        "Timeline": ""
    },
    {
        "Service_Type": "Service Improvement",
        "Event_Type": "Cutover",
        "Timeline": ""
    }
]

# Database Models
class Timeline(Base):
    __tablename__ = "timelines"
    id = Column(Integer, primary_key=True, index=True)
    Service_Type = Column(String(100), nullable=False)
    Event_Type = Column(String(100), nullable=False)
    Timeline = Column(String(50), nullable=True)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Optional: Add relationship to tasks
    tasks = relationship("Task", back_populates="user")

class Service(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    Service_Offerings_Major = Column(String(255), nullable=False)
    Service_Level = Column(String(50), nullable=False)
    Service_Type = Column(String(100), nullable=False)
    # Optional: Add relationship to tasks
    tasks = relationship("Task", back_populates="service")

# New Task Model
class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(String(500), nullable=True)
    service_id = Column(Integer, ForeignKey('services.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    status = Column(String(50), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    service = relationship("Service", back_populates="tasks")
    user = relationship("User", back_populates="tasks")

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

class ServiceResponse(BaseModel):
    id: int
    Service_Offerings_Major: str
    Service_Level: str
    Service_Type: str

    class Config:
        from_attributes = True

# Task Pydantic Models
class TaskCreate(BaseModel):
    name: str
    description: Optional[str] = None
    service_id: int
    user_id: int
    status: Optional[str] = "pending"

class TaskResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    service_id: int
    user_id: int
    status: str = "pending"
    created_at: datetime = datetime.utcnow()

    class Config:
        from_attributes = True

class TimelineResponse(BaseModel):
    Service_Type: str
    Event_Type: str
    Timeline: Optional[str]

    class Config:
        from_attributes = True

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper functions remain the same as in your original code...
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )

async def init_services_and_timelines(db: Session):
    # Check if services already exist
    existing_services = db.query(Service).first()
    if not existing_services:
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

    # Check if timelines already exist
    existing_timelines = db.query(Timeline).first()
    if not existing_timelines:
        # Generate timeline data
        TIMELINE_DATA = await timeline_generation(TEMPLATE_TIMELINE_DATA)
        
        # Add timelines from the generated data
        timelines_to_add = [
            Timeline(
                Service_Type=timeline['Service_Type'],
                Event_Type=timeline['Event_Type'],
                Timeline=timeline['Timeline']
            ) for timeline in TIMELINE_DATA
        ]
        
        db.add_all(timelines_to_add)
        db.commit()


# Startup event to initialize services
@router.on_event("startup")
async def startup():
    # Get a database session
    db = SessionLocal()
    try:
        await init_services_and_timelines(db)
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

### TASKS


@router.post("/tasks", response_model=TaskResponse)
async def create_task(task: TaskCreate, db: Session = Depends(get_db)):
    # Validate that user exists
    user = db.query(User).filter(User.id == task.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate that service exists
    service = db.query(Service).filter(Service.id == task.service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Create new task
    db_task = Task(
        name=task.name,
        description=task.description,
        service_id=task.service_id,
        user_id=task.user_id,
        status=task.status or "pending"
    )
    
    try:
        db.add(db_task)
        db.commit()
        db.refresh(db_task)
        return db_task
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/tasks/bulk", response_model=List[TaskResponse])
async def create_bulk_tasks(tasks: List[TaskCreate], db: Session = Depends(get_db)):
    # Validate all tasks before inserting
    user_ids = set(task.user_id for task in tasks)
    service_ids = set(task.service_id for task in tasks)
    
    # Check users exist
    existing_users = db.query(User.id).filter(User.id.in_(user_ids)).all()
    if len(existing_users) != len(user_ids):
        raise HTTPException(status_code=404, detail="One or more users not found")
    
    # Check services exist
    existing_services = db.query(Service.id).filter(Service.id.in_(service_ids)).all()
    if len(existing_services) != len(service_ids):
        raise HTTPException(status_code=404, detail="One or more services not found")
    
    # Create task objects
    db_tasks = [
        Task(
            name=task.name,
            description=task.description,
            service_id=task.service_id,
            user_id=task.user_id,
            status=task.status or "pending"
        ) for task in tasks
    ]
    
    try:
        db.add_all(db_tasks)
        db.commit()
        
        # Refresh to get IDs
        for task in db_tasks:
            db.refresh(task)
        
        return db_tasks
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/tasks/user/{user_id}", response_model=List[TaskResponse])
async def get_user_tasks(user_id: int, db: Session = Depends(get_db)):
    # Validate user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get all tasks for the user
    tasks = db.query(Task).filter(Task.user_id == user_id).all()
    return tasks

@router.get("/tasks/service/{service_id}", response_model=List[TaskResponse])
async def get_service_tasks(service_id: int, db: Session = Depends(get_db)):
    # Validate service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get all tasks for the service
    tasks = db.query(Task).filter(Task.service_id == service_id).all()
    return tasks

@router.get("/tasks/{user_id}/{service_id}", response_model=List[TaskResponse])
async def get_user_service_tasks(user_id: int, service_id: int, db: Session = Depends(get_db)):
    # Validate user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate service exists
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get tasks for the specific user and service
    tasks = db.query(Task).filter(
        Task.user_id == user_id, 
        Task.service_id == service_id
    ).all()
    
    return tasks

@router.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(task_id: int, task_update: TaskCreate, db: Session = Depends(get_db)):
    # Find existing task
    db_task = db.query(Task).filter(Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # Validate user and service if provided
    if task_update.user_id:
        user = db.query(User).filter(User.id == task_update.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
    
    if task_update.service_id:
        service = db.query(Service).filter(Service.id == task_update.service_id).first()
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
    
    # Update task fields
    db_task.name = task_update.name or db_task.name
    db_task.description = task_update.description or db_task.description
    db_task.service_id = task_update.service_id or db_task.service_id
    db_task.user_id = task_update.user_id or db_task.user_id
    db_task.status = task_update.status or db_task.status
    
    try:
        db.commit()
        db.refresh(db_task)
        return db_task
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.delete("/tasks/{task_id}")
async def delete_task(task_id: int, db: Session = Depends(get_db)):
    # Find existing task
    db_task = db.query(Task).filter(Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    try:
        db.delete(db_task)
        db.commit()
        return {"detail": "Task deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/service-analysis/{user_id}/{service_id}")
async def get_service_analysis(
    user_id: int,
    service_id: int, 
    db: Session = Depends(get_db)
):
    analysis = analyze_service_tasks(db, user_id, service_id)

    messages = [
    {
        "role": "user",
        "content": (
            f"Convert the JSON file into a paragraph, and return it. Dont add additional content. Dont add unwanted symbols and slashes in the paragraph, return as simple paragraph."
        ),
    },
    {
        "role": "assistant", 
        "content": str(analysis)
    }
    ]

    headers = {
        "Content-Type": "application/json",
        "api-key": settings.AZURE_OPENAI_API_KEY,
    }

    try:
        # Pass the messages list to the function
        summary = await azure_openai_call(messages, headers)

        return summary

        # return JSONResponse(
        #     content={"Analysis": analysis, "Summary": summary}
        # )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/timeline/{service_type}/{event_type}", response_model=TimelineResponse)
async def return_timeline(
    service_type: str, 
    event_type: str, 
    db: Session = Depends(get_db)
):
    # Find the timeline for the specific service type and event type
    timeline = db.query(Timeline).filter(
        Timeline.Service_Type == service_type,
        Timeline.Event_Type == event_type
    ).first()
    
    if not timeline:
        raise HTTPException(status_code=404, detail="Timeline not found")
    
    return timeline


