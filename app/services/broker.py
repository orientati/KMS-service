from __future__ import annotations

import json
import asyncio
import uuid
import aio_pika

from app.core.config import settings
from app.core.logging import get_logger, setup_logging

logger = get_logger(__name__)


class AsyncBrokerSingleton:
    """Singleton asincrono per la gestione della connessione a RabbitMQ e delle operazioni di publish/subscribe."""
    _instance = None

    def __new__(cls, service_name: str = settings.SERVICE_NAME):
        """Implementa il pattern Singleton per la classe AsyncBrokerSingleton.

        Args:
            service_name (str): Nome del servizio che utilizza il broker.
        """
        if cls._instance is None:
            setup_logging()
            logger.info("Starting async broker consumer...")
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, service_name: str = settings.SERVICE_NAME):
        """Inizializza il broker asincrono.

        Args:
            service_name (str): Nome del servizio che utilizza il broker.
        """
        if not hasattr(self, "initialized"):
            self.service_name = service_name
            self.connection = None
            self.channel = None
            self.queues = {}
            self.consumer_tags = {}
            self.initialized = True

    async def connect(self):
        """Stabilisce una connessione asincrona a RabbitMQ."""
        try:
            if self.connection and not self.connection.is_closed:
                return True

            self.connection = await aio_pika.connect_robust(
                host=settings.RABBITMQ_HOST,
                port=settings.RABBITMQ_PORT,
                login=settings.RABBITMQ_USER,
                password=settings.RABBITMQ_PASS
            )
            self.channel = await self.connection.channel()
            logger.info("Connected to RabbitMQ (aio-pika)")

            return True
        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            return False

    async def subscribe(self, exchange_name, callback, *, ex_type="direct", routing_key=""):
        """Sottoscrive a un exchange RabbitMQ con una callback specifica (asincrono).

        Args:
            exchange_name (str): Nome dell'exchange a cui sottoscriversi.
            callback (callable): Funzione di callback da chiamare quando arriva un messaggio.
            ex_type (str): Tipo di exchange (default: "direct").
            routing_key (str): Chiave di routing per il binding della coda (default: ""). Se vuota, si sottoscrive a tutti i messaggi dell'exchange.
        """
        exchange = await self.channel.declare_exchange(exchange_name, ex_type, durable=True)
        if routing_key:
            queue_name = f"{self.service_name}.{exchange_name}.{routing_key}"
        else:
            queue_name = f"{self.service_name}.{exchange_name}.all"

        queue = await self.channel.declare_queue(queue_name, durable=True)
        await queue.bind(exchange, routing_key=routing_key)

        # consume returns a consumer tag, it is NOT a blocking task that needs asyncio.create_task
        consumer_tag = await queue.consume(callback)

        self.queues[queue_name] = queue
        self.consumer_tags[queue_name] = consumer_tag
        logger.info(
            f"Subscribed to exchange {exchange_name} with queue '{queue_name}' and routing key '{routing_key}' (aio-pika)")

    async def unsubscribe(self, queue_name):
        """Annulla la sottoscrizione a una coda RabbitMQ (asincrono).

        Args:
            queue_name (str): Nome della coda da cui annullare la sottoscrizione.
        """
        if queue_name in self.consumer_tags:
            consumer_tag = self.consumer_tags[queue_name]
            if queue_name in self.queues:
                await self.queues[queue_name].cancel(consumer_tag)
            del self.consumer_tags[queue_name]

        if queue_name in self.queues:
            await self.queues[queue_name].unbind()
            # await self.queues[queue_name].delete() # Optional: decide if we want to delete the queue
            del self.queues[queue_name]
        logger.info(f"Unsubscribed from queue '{queue_name}' (aio-pika)")

    async def publish_message(self, exchange_name, msg_type, data, routing_key=""):
        """Pubblica un messaggio su un exchange RabbitMQ (asincrono).
        Args:
            exchange_name (str): Nome dell'exchange su cui pubblicare il messaggio.
            msg_type (str): Tipo di messaggio.
            data (dict): Dati del messaggio.
            routing_key (str): Chiave di routing per il messaggio (default: ""). Se vuota, il messaggio viene inviato a tutti i consumatori dell'exchange.
        """
        exchange = await self.channel.declare_exchange(exchange_name, "direct", durable=True)
        message = aio_pika.Message(
            body=json.dumps({
                "id": str(uuid.uuid4()),
                "type": msg_type,
                "data": data
            }).encode("utf-8"),
            content_type="application/json",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT
        )
        await exchange.publish(message, routing_key=routing_key)
        logger.info(
            f"Sent message to exchange {exchange_name}. Type: {msg_type}, Routing key: {routing_key} (aio-pika)")

    async def close(self):
        """Chiude la connessione a RabbitMQ e annulla tutte le sottoscrizioni (asincrono)."""
        for queue_name in list(self.consumer_tags.keys()):
            await self.unsubscribe(queue_name)
        if self.channel:
            await self.channel.close()
        if self.connection:
            await self.connection.close()
        logger.info("Closed all RabbitMQ consumer tasks (aio-pika)")


def declare_services_exchanges(exchanges: dict):
    """Dichiara e sottoscrive agli exchange RabbitMQ specificati nel dizionario exchanges (asincrono).

    Args:
        exchanges (dict): Dizionario con chiavi come nomi degli exchange e valori come funzioni di callback.
    """

    async def runner():
        broker_instance = AsyncBrokerSingleton()
        await broker_instance.connect()
        for exchange, callback in exchanges.items():
            await broker_instance.subscribe(exchange, callback)

    asyncio.run(runner())
