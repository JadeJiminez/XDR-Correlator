"""
Top-level entrypoint for XDR-Correlator.
"""

import threading

import uvicorn

from api.main import app, engine_ready
from xdr.correlator import main as correlator_main


def start_web_server():
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")


if __name__ == "__main__":
    server_thread = threading.Thread(target=start_web_server, daemon=True)
    server_thread.start()

    print("[*] Dashboard UI starting at http://localhost:8000")
    print("[*] Waiting for the CorrelationEngine to bind to the dashboard's event loop...")

    if not engine_ready.wait(timeout=10):
        raise RuntimeError(
            "CorrelationEngine never bound to the dashboard's event loop within 10s -- "
            "the dashboard server may have failed to start. Check the uvicorn output above."
        )

    print("[*] Engine bound.")
    input(
        "[*] Open http://localhost:8000 in your browser now, then press Enter here "
        "to begin PCAP replay (events broadcast before your browser connects are lost)...\n"
    )

    print("[*] Starting PCAP replay analysis...")
    correlator_main()

    print("\n[*] PCAP replay finished. Dashboard remains live at http://localhost:8000")
    print("[*] Press Ctrl+C to exit.")
    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
