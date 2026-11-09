
import os
import hmac
import hashlib
import json
import logging

from pathlib import Path
from dotenv import load_dotenv

from fastapi import FastAPI, Request, Header, HTTPException, BackgroundTasks


# Load environment variables
load_dotenv(Path(__file__).resolve().parent / ".env")

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

if not WEBHOOK_SECRET:
    raise ValueError("WEBHOOK_SECRET is missing in .env")


# Logging configuration
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Webhook Receiver API")


# Background event processing
def process_event(event_body: bytes):

    try:
        event = json.loads(event_body.decode("utf-8"))

        logging.info("Webhook event processed successfully")
        logging.info("Event data: %s", event)

    except Exception as error:
        logging.error("Error processing webhook: %s", error)


# Webhook endpoint
@app.post("/webhooks/customer-events")
async def receive_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_signature: str = Header(default=None)
):

    # 1. Read raw request body
    raw_body = await request.body()

    # 2. Check signature exists
    if not x_signature:
        raise HTTPException(
            status_code=401,
            detail="Missing signature"
        )

    # 3. Generate expected HMAC-SHA256 signature
    secret = WEBHOOK_SECRET.encode("utf-8")

    expected_signature = hmac.new(
        secret,
        raw_body,
        hashlib.sha256
    ).hexdigest()

    # 4. Compare signatures securely
    if not hmac.compare_digest(expected_signature, x_signature):
        raise HTTPException(
            status_code=401,
            detail="Invalid signature"
        )

    # 5. Process event in background
    background_tasks.add_task(process_event, raw_body)

    # 6. Return immediately after accepting valid event
    return {
        "status": "accepted"
    }


@app.get("/")
def home():
    return {"message": "Webhook Receiver is running"}
