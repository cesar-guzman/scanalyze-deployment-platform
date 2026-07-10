import logging

logger = logging.getLogger(__name__)

def get_next_stage(document_route: str) -> str:
    """
    Router central basado en document_route para decidir la siguiente etapa.
    """
    # Enforce strictly known routes
    route_map = {
        'bank': 'bank-extract',
        'gov': 'gov-extract',
        'personal': 'personal-extract',
        'platform': 'classify',
        'default': 'classify'
    }
    
    next_stage = route_map.get(document_route)
    if not next_stage:
        logger.error(f"Unrecognized document_route: {document_route}. Cannot determine next_stage.")
        raise ValueError(f"Unrecognized document_route: {document_route}")
        
    return next_stage
