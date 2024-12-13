from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime
from fastapi.responses import JSONResponse
import bcrypt
import asyncio
from langchain.prompts import ChatPromptTemplate
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnableParallel, RunnableLambda
from langchain_openai import AzureChatOpenAI
import os

from fastapi import APIRouter
from typing import List, Optional

from app.services.service_analysis import analyze_service_tasks
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

async def init_services(db: Session):
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

# Startup event to initialize services
@router.on_event("startup")
async def startup():
    # Get a database session
    db = SessionLocal()
    try:
        await init_services(db)
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

@router.get("/services/by-id/{service_id}", response_model=List[ServiceResponse])
async def get_services_by_id(service_id: int, db: Session = Depends(get_db)):
    services = db.query(Service).filter(Service.id== service_id).all()
    if not services:
        raise HTTPException(status_code=404, detail="No services found for this type")
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

@router.get("/timeline/{user_id}/{service_id}/{activity}")
async def return_timeline(user_id: int, service_id: int, activity: str, db: Session = Depends(get_db)):
    try:
        # Validate user exists
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        # Validate service exists and get service name
        service = db.query(Service).filter(Service.id == service_id).first()
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")

        service_name = service.Service_Type

        tasks = db.query(Task).filter(
            Task.user_id == user_id, 
            Task.service_id == service_id
        ).all()

        task_summary = ""
        
        for task in tasks:
            task_summary += f"The task name is {task.name}. "
            task_summary += f"The task description is {task.description}. "

        model = AzureChatOpenAI(model="gpt-4o", api_version='2024-02-15-preview')
        prompt_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert analyst specializing in evaluating services and their associated tasks."),
                (
                    "human", 
                    (
                        "Given is the service name, {service_name}, activity {activity} and task summary of this service, {task_summary}.\n"
                        "By considering this 3 datas alone, return me the minimum number of days required to complete the tasks associated with this service.\n"
                    )
                ),
            ]
        )

        def analyze_timeline(features):
            timeline_template = ChatPromptTemplate.from_messages(
                [
                    ("system", "You are an expert in finding out the minimum number of days to complete a set of tasks."),
                    (
                        "human",
                        "Given these features: {features}, return the required days in numbers, example: 12",
                    ),
                ]
            )
            return timeline_template.format_prompt(features=features)

    
        timeline_chain = (
            RunnableLambda(lambda x: analyze_timeline(x)) | model | StrOutputParser()
        )
        
        def combine_reponse(timeline):
            result = {
            "timeline": timeline
            }
            # Return the dictionary as a JSON response
            return JSONResponse(result)

        chain = (
            prompt_template
            | model
            | StrOutputParser()
            | RunnableParallel(branches={"timeline": timeline_chain})
            | RunnableLambda(lambda x: combine_reponse(x["branches"]["timeline"]))
        )

        result = chain.invoke({"activity": activity, "service_name": service_name, "task_summary": task_summary})
        return result

    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

#################

@router.get("/canvas/service-analysis")
async def get_service_analysis(
    request: dict,
    db: Session = Depends(get_db)
):
    user_id = request.get('user_id')
    service_ids = request.get('service_ids', [])
    analysis = analyze_service_tasks(db, user_id, service_ids)

    os.environ["OPENAI_API_VERSION"] = "2024-02-15-preview"
    os.environ["AZURE_OPENAI_ENDPOINT"] = settings.AZURE_OPENAI_ENDPOINT
    os.environ["AZURE_OPENAI_API_KEY"] = settings.AZURE_OPENAI_API_KEY

    model = AzureChatOpenAI(model="gpt-4o", max_tokens=4000)
    prompt_template = ChatPromptTemplate.from_messages(
        [
            ("system", "You are an expert analyst specializing in evaluating services and their associated tasks."),
            (
                "human", 
                (
                    "Given the following details about the service '{data}' and its tasks, analyze and provide the following:\n"
                    "1. The criticality of the service and its tasks. Explain why they are critical or not.\n"
                    "2. The complexity of the tasks, considering the processes, dependencies, and technical requirements.\n"
                    "3. The estimated effort required to complete these tasks, highlighting the factors contributing to the effort estimation.\n\n"
                )
            ),
        ]
    )  

    def analyze_criticality(features):
        criticality_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert in finding out the criticality."),
                (
                    "human",
                    "Given these features: {features}, return the criticality in single word. either low/medium/high.",
                ),
            ]
        )
        return criticality_template.format_prompt(features=features)

    def analyze_complexity(features):
        complexity_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert in finding out the complexity."),
                (
                    "human",
                    "Given these features: {features}, return the complexity in single word. either low/medium/high.",
                ),
            ]
        )
        return complexity_template.format_prompt(features=features)

    def analyze_effort(features):
        effort_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert in finding out the effort."),
                (
                    "human",
                    "Given these features: {features}, return the effort in single word. either low/medium/high.",
                ),
            ]
        )
        return effort_template.format_prompt(features=features)

    def analyze_data(features):
        analyze_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert in analysis."),
                (
                    "human",
                    "Convert the JSON file into a paragraph, and return it. Dont add additional content. Dont add unwanted symbols and slashes in the paragraph, return as simple paragraph. {features}. either low/medium/high.",
                ),
            ]
        )
        return analyze_template.format_prompt(features=features)
    

    # Simplify branches with LCEL
    criticality_chain = (
        RunnableLambda(lambda x: analyze_criticality(x)) | model | StrOutputParser()
    )

    complexity_chain = (
        RunnableLambda(lambda x: analyze_complexity(x)) | model | StrOutputParser()
    )
    effort_chain = (
        RunnableLambda(lambda x: analyze_effort(x)) | model | StrOutputParser()
    )
    analysis_chain = (
        RunnableLambda(lambda x: analyze_data(x)) | model | StrOutputParser()
    )

    def combine_reponse(criticality, complexity, effort, analysis):
        result = {
        "criticality": criticality,
        "complexity": complexity,
        "effort": effort,
        "analysis": analysis
        }
        # Return the dictionary as a JSON response
        return JSONResponse(content=result)


    chain = (
        prompt_template
        | model
        | StrOutputParser()
        | RunnableParallel(branches={"criticality": criticality_chain, "complexity": complexity_chain, "effort": effort_chain, "analysis": analysis_chain})
        | RunnableLambda(lambda x: combine_reponse(x["branches"]["criticality"], x["branches"]["complexity"] , x["branches"]["effort"] , x["branches"]["analysis"]))
    )


    try:
        result = chain.invoke({"data": str(analysis)})
        return result
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/service-analysis-test")
async def get_service_analysis(
    request: dict,
    db: Session = Depends(get_db)
):
    user_id = request.get('user_id')
    service_ids = request.get('service_ids', [])
    analysis = await analyze_service_tasks(db, user_id, service_ids)
    # return analysis
    service_analysis_result = {}
    for service_type, report in analysis.items():
        # Use analysis_langchain to get detailed analysis for each service type
        detailed_analysis = await analysis_langchain(report)
        
        # Store the detailed analysis under the service type key
        service_analysis_result[service_type] = detailed_analysis
    
    return service_analysis_result

async def analysis_langchain(report: any):
    model = AzureChatOpenAI(model="gpt-4o", api_version='2024-02-15-preview')
    prompt_template = ChatPromptTemplate.from_messages(
        [
            ("system", "You are an expert analyst specializing in evaluating services and their associated tasks."),
            (
                "human", 
                (
                    "Given the following details about the service '{data}' and its tasks, analyze and provide the following:\n"
                    "1. The criticality of the service and its tasks. Explain why they are critical or not.\n"
                    "2. The complexity of the tasks, considering the processes, dependencies, and technical requirements.\n"
                    "3. The estimated effort required to complete these tasks, highlighting the factors contributing to the effort estimation.\n\n"
                )
            ),
        ]
    )  

    def analyze_criticality(features):
        criticality_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert in finding out the criticality."),
                (
                    "human",
                    "Given these features: {features}, return the criticality in strictly single word, either low/high. Eg. High",
                ),
            ]
        )
        return criticality_template.format_prompt(features=features)

    def analyze_complexity(features):
        complexity_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert in finding out the complexity."),
                (
                    "human",
                    "Given these features: {features}, return the complexity in strictly single word. either low/high. Eg. Low",
                ),
            ]
        )
        return complexity_template.format_prompt(features=features)

    def analyze_effort(features):
        effort_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert in finding out the effort."),
                (
                    "human",
                    "Given these features: {features}, return the effort in single word. either low/high.",
                ),
            ]
        )
        return effort_template.format_prompt(features=features)

    def analyze_data(features):
        analyze_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert in analysis."),
                (
                    "human",
                    "Convert the JSON file into a paragraph, and return it. Dont add additional content. Dont add unwanted symbols and slashes in the paragraph, return as simple paragraph. {features}. either low/medium/high.",
                ),
            ]
        )
        return analyze_template.format_prompt(features=features)


    # Simplify branches with LCEL
    criticality_chain = (
        RunnableLambda(lambda x: analyze_criticality(x)) | model | StrOutputParser()
    )

    complexity_chain = (
        RunnableLambda(lambda x: analyze_complexity(x)) | model | StrOutputParser()
    )
    effort_chain = (
        RunnableLambda(lambda x: analyze_effort(x)) | model | StrOutputParser()
    )
    analysis_chain = (
        RunnableLambda(lambda x: analyze_data(x)) | model | StrOutputParser()
    )

    def combine_reponse(criticality, complexity, effort, analysis):
        result = {
        "criticality": criticality,
        "complexity": complexity,
        "effort": effort,
        "analysis": analysis
        }
        # Return the dictionary as a JSON response
        return result


    chain = (
        prompt_template
        | model
        | StrOutputParser()
        | RunnableParallel(branches={"criticality": criticality_chain, "complexity": complexity_chain, "effort": effort_chain, "analysis": analysis_chain})
        | RunnableLambda(lambda x: combine_reponse(x["branches"]["criticality"], x["branches"]["complexity"] , x["branches"]["effort"] , x["branches"]["analysis"]))
    )


    try:
        result = chain.invoke({"data": str(report)})
        return result
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/grouped-tasks") #given a user and multiple service ids, it will return group of tasks spanning the given service ids
async def get_grouped_tasks(
    request: dict, 
    db: Session = Depends(get_db)
):
    user_id = request.get('user_id')
    service_ids = request.get('service_ids', [])

    # Validate user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate services exist
    for service_id in service_ids:
        service = db.query(Service).filter(Service.id == service_id).first()
        if not service:
            raise HTTPException(status_code=404, detail=f"Service with ID {service_id} not found")
    
    # Query tasks for the user and specified services
    tasks_query = db.query(Task, Service).join(Service, Task.service_id == Service.id)\
        .filter(Task.user_id == user_id, Task.service_id.in_(service_ids))
    
    # Group tasks by service type
    grouped_tasks = {}
    for task, service in tasks_query:
        if service.Service_Type not in grouped_tasks:
            grouped_tasks[service.Service_Type] = []
        
        grouped_tasks[service.Service_Type].append({
            # 'service_id': task.service_id,
            # 'user_id': task.user_id,
            # 'task_id': task.id,
            'task_name': task.name,
            'task_description': task.description
        })
    
    return grouped_tasks

##########################

