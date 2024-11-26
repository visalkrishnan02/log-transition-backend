import logging

def setup_logging():
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    logger.debug("Logging is set up.")
    return logger

logger = setup_logging()