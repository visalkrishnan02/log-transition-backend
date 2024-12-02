from typing import List
import dspy
import logging
from logging.handlers import RotatingFileHandler
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException

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

class TimelineGenerationSignature(dspy.Signature):
    service_type = dspy.InputField()
    event_type = dspy.InputField()
    timeline = dspy.OutputField(desc = "Generate minimum required number of days required to complete the event_type of service_type. Return in the format : x days. **CRITICAL REQUIREMENT :- YOU SHOULD ONLY RETURN THE NUMBER OF DAYS**")

class TimelineCreation(dspy.Module):
    def __init__(self):
        super().__init__()
        self.timeline_creator = dspy.ChainOfThought(TimelineGenerationSignature)

    def forward(self, Timeline_Data):
        try:
            for x in Timeline_Data:       
                timeline_create = self.timeline_creator(service_type = x["Service_Type"], event_type = x["Event_Type"])
                x["Timeline"] = timeline_create.timeline
            return Timeline_Data
        except Exception as e:
            logger.error(f"Error in TimelineCreation forward function: {str(e)}")
            raise

def timeline_creation(Timeline_Data):
    try:
        creation = TimelineCreation()
        result = creation(Timeline_Data)
        return result
    except Exception as e:
        logger.error(f"Failed to create timeline: {str(e)}")
        raise

async def timeline_generation(Timeline_Data):
    try:
        New_Timeline_Data = timeline_creation(Timeline_Data = Timeline_Data)
        return New_Timeline_Data
    except Exception as e:
        logger.error(f"Service analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Timeline Generation Failed: {str(e)}")