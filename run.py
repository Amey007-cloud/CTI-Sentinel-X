from __future__ import annotations
import os
from app import app, startup


def main():
    startup()
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    print("CTI Sentinel X web UI: http://localhost:%s" % port)
    print("The FastAPI assistant must also be running at CHAT_API_URL.")
    app.run(host=host, port=port, debug=os.getenv("FLASK_DEBUG", "0") == "1")

if __name__ == "__main__":
    main()
