from __future__ import annotations

from app.core.config import settings
from app.core.logging import get_logger
import traceback

logger = get_logger(__name__)

# Classi e Enum per gestire richieste HTTP in modo strutturato
API_PREFIX = settings.API_PREFIX

class OrientatiException(Exception):
    """Eccezione personalizzata generica per l'applicazione Orientati.
    Attributes:
        status_code (int | None): Codice di stato HTTP della risposta, se disponibile.
        message (str): Messaggio di errore generale.
        details (dict | None): Dettaglio del messaggio di errore.
        url (str): URL della richiesta che ha causato l'errore.
        exc (Exception | None): Eccezione originale, se presente.
    """

    def __init__(self, message: str = "Internal Server Error", status_code: int = 500, details: dict | None = None, url: str = None, exc: Exception = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details if details is not None else {"message": "Internal Server Error"}
        self.url = url
        caller_stack = "".join(traceback.format_stack()[:-1])
        logger.error("ERRORE!\n")
        logger.error(f"Stack del richiamante:\n{caller_stack}")
        if exc is not None:
            exc_tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            logger.error(f"ECCEZIONE ORIGINALE:\n{exc_tb}")