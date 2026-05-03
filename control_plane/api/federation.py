import base64
import io
import threading
import torch

_clients = []
_clients_lock = threading.Lock()
FED_ROUND_SIZE = 3

def handle_federation(payload_b64: str) -> dict:
    data = base64.b64decode(payload_b64)
    buffer = io.BytesIO(data)
    state_dict = torch.load(buffer, map_location="cpu", weights_only=True)

    with _clients_lock:
        _clients.append(state_dict)
        current_count = len(_clients)

        if current_count >= FED_ROUND_SIZE:
            aggregated = _aggregate_weights(_clients)
            _clients.clear()

            out_buf = io.BytesIO()
            torch.save(aggregated, out_buf)
            return {
                "status": "round_complete",
                "aggregated_weights": base64.b64encode(
                    out_buf.getvalue()
                ).decode(),
            }

    return {
        "status": "pending",
        "message": f"Waiting for other nodes: {current_count}/{FED_ROUND_SIZE} received",
    }

def _aggregate_weights(clients: list):
    aggregated = {}
    for key in clients[0].keys():
        aggregated[key] = sum(c[key] for c in clients) / len(clients)
    return aggregated
