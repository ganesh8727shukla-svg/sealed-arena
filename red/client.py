import urllib.request
import json
import time
import uuid

BROKER_URL = "http://broker:8000/message"

time.sleep(2)

message = {
    "source": "red",
    "type": "test",
    "message": "RED TEAM MESSAGE"
}

data = json.dumps(message).encode()

request = urllib.request.Request(
    BROKER_URL,
    data=data,
    headers={
        "Content-Type": "application/json",
        "Idempotency-Key": str(uuid.uuid4()),
    },
    method="POST"
)

try:
    with urllib.request.urlopen(request) as response:
        result = json.loads(response.read().decode())
        print(json.dumps({
            "service": "red",
            "status": "submitted",
            "broker_event_id": result.get("event_id"),
        }), flush=True)

except Exception as error:
    print(json.dumps({
        "service": "red",
        "status": "failed",
        "error_type": type(error).__name__,
    }), flush=True)
