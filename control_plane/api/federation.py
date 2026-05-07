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
            try:
                aggregated = _aggregate_weights(_clients)
            except ValueError as e:
                _clients.clear()
                return {"status": "error", "message": str(e)}
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
    reference_keys = set(clients[0].keys())
    for i, client in enumerate(clients[1:], 1):
        if set(client.keys()) != reference_keys:
            raise ValueError(
                f"Client {i} has mismatched keys: "
                f"expected {reference_keys}, got {set(client.keys())}"
            )
    aggregated = {}
    for key in clients[0].keys():
        tensors = [c[key] for c in clients]
        if any(t.shape != tensors[0].shape for t in tensors[1:]):
            raise ValueError(
                f"Shape mismatch for key '{key}': "
                f"{[t.shape for t in tensors]}"
            )
        aggregated[key] = sum(tensors) / len(tensors)
    return aggregated
