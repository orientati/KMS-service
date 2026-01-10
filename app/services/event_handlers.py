from app.core.logging import get_logger
from app.services.token_service import _invalidate_cache

logger = get_logger(__name__)

async def handle_key_rotated(message):
    """
    Callback per l'evento KMS.KEY_ROTATED.
    Invalida la cache locale delle chiavi.
    """
    try:
        data = message.body.decode()
        logger.info(f"Ricevuto evento KMS.KEY_ROTATED: {data}")
        _invalidate_cache()
    except Exception as e:
        logger.error(f"Errore nella gestione dell'evento KMS.KEY_ROTATED: {e}")
