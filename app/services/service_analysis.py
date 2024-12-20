import dspy
import logging
from logging.handlers import RotatingFileHandler
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException
  

from app.core.config import settings
from typing import List

from app.services.openai_call import azure_openai_call

# Logging setup
log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file = 'service_analysis.log'
handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=10)
handler.setFormatter(log_formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logging.basicConfig(level=logging.INFO, handlers=[handler, console_handler])
logger = logging.getLogger(__name__)

# Azure OpenAI Configuration (Consider using environment variables for sensitive info)
API_KEY = settings.AZURE_OPENAI_API_KEY  # Replace with secure method of storing API key
ENDPOINT = settings.AZURE_OPENAI_ENDPOINT

# Configure DSPy with Azure OpenAI
turbo = dspy.AzureOpenAI(
    api_base=ENDPOINT,
    api_version='2024-02-15-preview', 
    model='gpt-4o-001', 
    api_key=API_KEY, 
    max_tokens=4000
)
dspy.settings.configure(lm=turbo, cache=False)

class ServiceComplexitySignature(dspy.Signature):
    """Analyze overall service complexity considering all tasks."""
    service_type = dspy.InputField()
    tasks_description = dspy.InputField()
    complexity_assessment = dspy.OutputField(
        desc="Overall complexity level (High/Moderate/Low) with brief justification"
    )

class ServiceCriticalitySignature(dspy.Signature):
    """Evaluate overall service criticality."""
    service_type = dspy.InputField()
    tasks_description = dspy.InputField()
    criticality_assessment = dspy.OutputField(
        desc="Overall criticality level (High/Moderate/Low) with brief justification"
    )

class ServiceEffortSignature(dspy.Signature):
    """Estimate overall service effort requirements."""
    service_type = dspy.InputField()
    tasks_description = dspy.InputField()
    effort_assessment = dspy.OutputField(
        desc="Required IT support team composition and resource requirements"
    )

class ServiceAnalysis(dspy.Module):
    def __init__(self):
        super().__init__()
        self.complexity_predictor = dspy.ChainOfThought(ServiceComplexitySignature)
        self.criticality_predictor = dspy.ChainOfThought(ServiceCriticalitySignature)
        self.effort_predictor = dspy.ChainOfThought(ServiceEffortSignature)
    
    def forward(self, service_type, tasks):
        try:
            # Convert tasks list to a formatted string description
            tasks_description = self.format_tasks(tasks)
            
            complexity_pred = self.complexity_predictor(
                service_type=service_type,
                tasks_description=tasks_description
            )
            
            criticality_pred = self.criticality_predictor(
                service_type=service_type,
                tasks_description=tasks_description
            )
            
            effort_pred = self.effort_predictor(
                service_type=service_type,
                tasks_description=tasks_description
            )
            
            return {
                'complexity': complexity_pred.complexity_assessment,
                'criticality': criticality_pred.criticality_assessment,
                'effort': effort_pred.effort_assessment
            }
        except Exception as e:
            logger.error(f"Error in service analysis: {str(e)}")
            raise

    def format_tasks(self, tasks):
        """Format tasks list into a string description."""
        formatted_tasks = []
        for task in tasks:
            formatted_tasks.append(f"{task['name']}: {task['description'] or 'No description'}")
        return " | ".join(formatted_tasks)

async def analyze_service(service_type, tasks):
    """Analyze an entire service based on all its tasks."""
    def format_tasks(tasks):
        """Format tasks list into a string description."""
        formatted_tasks = []
        for task in tasks:
            formatted_tasks.append(f"{task['name']}: {task['description'] or 'No description'}")
        return " | ".join(formatted_tasks)

    tasks_formatted = format_tasks(tasks)
    try:
        # analyzer = ServiceAnalysis()
        # analysis = analyzer(
        #     service_type=service_type,
        #     tasks=tasks
        # )
        messages = [
        {
            "role": "user",
            "content": (
                f"""I have a group of tasks from a particular service type. The tasks are {tasks_formatted} and the service type is {service_type}.
                I want an analysis report of this tasks revolving the service type. I want the complexity, criticality of the tasks and the effort
                required to execute the tasks. The complexity and criticality should be strictly mentioned either 'High' or 'Low'."""
            ),
        }
        ]

        headers = {
            "Content-Type": "application/json",
            "api-key": settings.AZURE_OPENAI_API_KEY,
        }
        analysis = await azure_openai_call(messages, headers)
        return analysis
    except Exception as e:
        logger.error(f"Failed to analyze service type{service_type}: {str(e)}")
        raise

async def analyze_service_tasks(db: Session, user_id: int, service_ids: List[int]):
    """
    Analyze tasks for multiple services and user from the database
   
    Args:
        db (Session): Database session
        user_id (int): ID of the user
        service_ids (List[int]): List of service IDs
    Returns:
        dict: Service type analysis results
    """
    try:
        from app.api.router import Task, Service, User
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
                'name': task.name,
                'description': task.description
            })
       
        # Perform analysis for each service type
        service_type_analyses = {}
        for service_type, tasks in grouped_tasks.items():
            # Perform service analysis for this service type
            analysis = await analyze_service(
                service_type=service_type,
                tasks=tasks
            )
            service_type_analyses[service_type.lower()] = analysis
       
        return service_type_analyses

    except Exception as e:
        logger.error(f"Service analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Service analysis failed: {str(e)}")