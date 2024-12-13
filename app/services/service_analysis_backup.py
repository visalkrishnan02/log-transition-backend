import dspy
import logging
from logging.handlers import RotatingFileHandler
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException
from app.api.router import Task, Service

from app.core.config import settings

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
    
    def forward(self, service_name, service_type, tasks):
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
                'service_name': service_name,
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

def analyze_service(service_name, service_type, tasks):
    """Analyze an entire service based on all its tasks."""
    try:
        analyzer = ServiceAnalysis()
        analysis = analyzer(
            service_name=service_name,
            service_type=service_type,
            tasks=tasks
        )
        return analysis
    except Exception as e:
        logger.error(f"Failed to analyze service {service_name}: {str(e)}")
        raise

def analyze_service_tasks(db: Session, user_id: int, service_id: int):
    
    try:
        tasks = db.query(Task).filter(
            Task.service_id == service_id, 
            Task.user_id == user_id
        ).all()
        
        # Get service details
        service = db.query(Service).filter(Service.id == service_id).first()
        
        if not service or not tasks:
            raise HTTPException(status_code=404, detail="No tasks found for this service and user")
        
        # Convert tasks to a format compatible with analysis
        task_list = [
            {
                'name': task.name, 
                'description': task.description
            } for task in tasks
        ]
        
        # Perform service analysis
        analysis = analyze_service(
            service_name=service.Service_Offerings_Major,
            service_type=service.Service_Type,
            tasks=task_list
        )

        return analysis

    except Exception as e:
        logger.error(f"Service analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Service analysis failed: {str(e)}")