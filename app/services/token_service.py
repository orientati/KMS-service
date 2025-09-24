from __future__ import annotations

import jwt
import logging
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import settings
from app.schemas.token import TokenResponse, TokenCreate

logger = logging.getLogger(__name__)


def create_token(data: TokenCreate) -> str:
    private_key_path = get_current_private_key_path()
    with open(private_key_path, "rb") as key_file:
        private_key = key_file.read()

    payload = data.model_dump()
    if "exp" not in payload:
        payload["exp"] = int((datetime.now(timezone.utc) + timedelta(minutes=30)).timestamp())
    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256"
    )
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def verify_token(token: str) -> TokenResponse:
    from jwt import InvalidTokenError

    public_keys = list_available_public_keys()
    last_error = None
    for key_info in public_keys:
        try:
            with open(key_info['path'], "rb") as key_file:
                public_key = key_file.read()
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False}
            )
            now = datetime.now(timezone.utc).timestamp()
            exp = payload.get("exp", now + 1)
            expired = now > exp
            response_data = {
                **payload,
                "verified": True,
                "expired": expired,
                "expires_at": int(exp)
            }
            return TokenResponse(**response_data)
        except Exception as e:
            last_error = e
            continue
    raise InvalidTokenError(f"Token non valido: {last_error}")


def create_secret_keys() -> dict:
    """
    Crea una nuova coppia di chiavi RSA e gestisce la rotazione.

    Returns:
        dict: Informazioni sulla creazione delle chiavi
    """
    try:
        private_dir = Path(settings.PRIVATE_KEY_PATH)
        public_dir = Path(settings.PUBLIC_KEY_PATH)
        private_dir.mkdir(parents=True, exist_ok=True)
        public_dir.mkdir(parents=True, exist_ok=True)

        # Genera timestamp per i nomi file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        logger.info(f"Inizio rotazione chiavi - timestamp: {timestamp}")

        # Genera nuova coppia di chiavi RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Backup della chiave privata attuale (se esiste)
        current_private_path = private_dir / settings.PRIVATE_KEY_FILENAME
        if current_private_path.exists():
            backup_name = f"{timestamp}_old_private.pem"
            backup_path = private_dir / backup_name
            shutil.copy2(current_private_path, backup_path)
            logger.info(f"Backup chiave privata creato: {backup_path}")

        # Salva la nuova chiave privata (sostituisce quella esistente)
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(current_private_path, 'wb') as f:
            f.write(pem_private)

        # Salva la nuova chiave pubblica con timestamp
        public_filename = f"{timestamp}_public.pem"
        public_path = public_dir / public_filename

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(public_path, 'wb') as f:
            f.write(pem_public)

        logger.info(f"Nuova chiave privata salvata: {current_private_path}")
        logger.info(f"Nuova chiave pubblica salvata: {public_path}")

        return {
            'timestamp': timestamp,
            'private_key_path': str(current_private_path),
            'public_key_path': str(public_path),
            'key_size': 2048,
            'status': 'success'
        }

    except Exception as e:
        logger.error(f"Errore durante la creazione delle chiavi: {e}")
        raise


def cleanup_old_public_keys(max_age_days: int = 30) -> List[str]:
    """
    Elimina le chiavi pubbliche più vecchie di max_age_days giorni.

    Args:
        max_age_days: Numero massimo di giorni per mantenere le chiavi pubbliche

    Returns:
        List[str]: Lista dei file eliminati
    """
    try:
        public_dir = Path(settings.PUBLIC_KEY_PATH)
        if not public_dir.exists():
            return []

        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        deleted_files = []

        # Cerca tutti i file .pem nella directory pubblica
        for file_path in public_dir.glob("*_public.pem"):
            try:
                # Estrae il timestamp dal nome del file
                timestamp_str = file_path.stem.split('_')[0] + '_' + file_path.stem.split('_')[1]
                file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                # Se il file è troppo vecchio, lo elimina
                if file_date < cutoff_date:
                    file_path.unlink()
                    deleted_files.append(str(file_path))
                    logger.info(f"Chiave pubblica eliminata (troppo vecchia): {file_path}")

            except (ValueError, IndexError) as e:
                # Se non riesce a leggere la data dal nome, salta il file
                logger.warning(f"Impossibile leggere la data dal file {file_path}: {e}")
                continue

        if deleted_files:
            logger.info(f"Eliminate {len(deleted_files)} chiavi pubbliche obsolete")
        else:
            logger.info("Nessuna chiave pubblica obsoleta da eliminare")

        return deleted_files

    except Exception as e:
        logger.error(f"Errore durante la pulizia delle chiavi pubbliche: {e}")
        raise


def cleanup_old_private_backups(max_backups: int = 5) -> List[str]:
    """
    Mantiene solo gli ultimi N backup delle chiavi private.

    Args:
        max_backups: Numero massimo di backup da mantenere

    Returns:
        List[str]: Lista dei file eliminati
    """
    try:
        private_dir = Path(settings.PRIVATE_KEY_PATH)
        if not private_dir.exists():
            return []

        # Trova tutti i backup delle chiavi private
        backup_files = list(private_dir.glob("*_old_private.pem"))

        if len(backup_files) <= max_backups:
            return []

        # Ordina per data di modifica (più recente prima)
        backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        # Elimina i backup più vecchi
        deleted_files = []
        for old_backup in backup_files[max_backups:]:
            old_backup.unlink()
            deleted_files.append(str(old_backup))
            logger.info(f"Backup privato eliminato: {old_backup}")

        logger.info(f"Eliminati {len(deleted_files)} backup privati obsoleti")
        return deleted_files

    except Exception as e:
        logger.error(f"Errore durante la pulizia dei backup privati: {e}")
        raise


def rotate_keys(cleanup_public_days: int = 30, max_private_backups: int = 5) -> dict:
    """
    Esegue la rotazione completa delle chiavi: crea nuove chiavi e pulisce quelle vecchie.

    Args:
        cleanup_public_days: Giorni dopo i quali eliminare le chiavi pubbliche
        max_private_backups: Numero massimo di backup privati da mantenere

    Returns:
        dict: Risultato dell'operazione di rotazione
    """
    try:
        logger.info("Inizio rotazione completa delle chiavi")

        # Crea nuove chiavi
        key_result = create_secret_keys()

        # Pulisci chiavi pubbliche vecchie
        deleted_public = cleanup_old_public_keys(cleanup_public_days)

        # Pulisci backup privati vecchi
        deleted_private_backups = cleanup_old_private_backups(max_private_backups)

        result = {
            **key_result,
            'deleted_public_keys': deleted_public,
            'deleted_private_backups': deleted_private_backups,
            'cleanup_summary': {
                'public_keys_deleted': len(deleted_public),
                'private_backups_deleted': len(deleted_private_backups)
            }
        }

        logger.info("Rotazione chiavi completata con successo")
        return result

    except Exception as e:
        logger.error(f"Errore durante la rotazione delle chiavi: {e}")
        raise


def get_current_private_key_path() -> str:
    """
    Restituisce il percorso della chiave privata attualmente attiva.
    Se la chiave non esiste, la crea tramite rotate_keys().

    Returns:
        str: Percorso della chiave privata attiva
    """
    private_key_path = Path(settings.PRIVATE_KEY_PATH) / settings.PRIVATE_KEY_FILENAME
    if not private_key_path.exists():
        rotate_keys()
    return str(private_key_path)

def list_available_public_keys() -> List[dict]:
    """
    Lista tutte le chiavi pubbliche disponibili con le loro informazioni.

    Returns:
        List[dict]: Lista delle chiavi pubbliche con timestamp e percorso
    """
    try:
        public_dir = Path(settings.PUBLIC_KEY_PATH)
        if not public_dir.exists():
            return []

        public_keys = []
        for file_path in public_dir.glob("*_public.pem"):
            try:
                # Estrae il timestamp dal nome del file
                timestamp_str = file_path.stem.split('_')[0] + '_' + file_path.stem.split('_')[1]
                file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                public_keys.append({
                    'timestamp': timestamp_str,
                    'date': file_date,
                    'path': str(file_path),
                    'age_days': (datetime.now() - file_date).days
                })

            except (ValueError, IndexError):
                continue

        # Ordina per data (più recente prima)
        public_keys.sort(key=lambda x: x['date'], reverse=True)

        return public_keys

    except Exception as e:
        logger.error(f"Errore nel listing delle chiavi pubbliche: {e}")
        return []
