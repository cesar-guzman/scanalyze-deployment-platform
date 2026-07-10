from abc import ABC, abstractmethod
from typing import Dict, Any
from ..contracts import ValidationResult

class BaseValidator(ABC):
    @abstractmethod
    def validate(self, document_id: str, payload: Dict[str, Any], tenant: str = "platform") -> ValidationResult:
        """
        Validates the parsed JSON payload from S3 and returns a ValidationResult.
        """
        pass
