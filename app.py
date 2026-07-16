"""
Backend Flask du chatbot SOC/Wazuh.
Expose l'interface web et l'API /api/chat qui orchestre l'agent IA.
"""
import os
import uuid
import logging

from flask import Flask, render_template, request, jsonify, session
from dotenv import load_dotenv

from wazuh_client import WazuhClient
from wazuh_indexer import WazuhIndexer
from agent import WazuhChatAgent

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wazuh-chatbot")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

wazuh_client = WazuhClient(
    base_url=os.getenv("WAZUH_API_URL"),
    user=os.getenv("WAZUH_API_USER"),
    password=os.getenv("WAZUH_API_PASSWORD"),
    verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true",
)
wazuh_indexer = WazuhIndexer(
    base_url=os.getenv("WAZUH_INDEXER_URL"),
    user=os.getenv("WAZUH_INDEXER_USER"),
    password=os.getenv("WAZUH_INDEXER_PASSWORD"),
    verify_ssl=os.getenv("WAZUH_INDEXER_VERIFY_SSL", "false").lower() == "true",
)
agent = WazuhChatAgent(wazuh_client, wazuh_indexer)

# Historique de conversation en mémoire, par session (suffisant pour un TP / démo).
# Pour de la production : remplacer par Redis ou une base de données.
conversations = {}


@app.route("/")
def index():
    session.setdefault("session_id", str(uuid.uuid4()))
    return render_template("index.html")


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json(force=True, silent=True) or {}
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "Message vide"}), 400

    session_id = session.get("session_id") or str(uuid.uuid4())
    session["session_id"] = session_id
    history = conversations.get(session_id, [])

    try:
        answer, full_messages = agent.chat(history, user_message)
    except Exception as e:
        logger.exception("Erreur lors de l'appel à l'agent")
        return jsonify({"error": f"Erreur agent : {e}"}), 500

    # On ne garde en mémoire que les tours user/assistant (pas les tool calls)
    # pour garder un contexte léger d'une conversation à l'autre.
    simplified = [m for m in full_messages if m.get("role") in ("user", "assistant") and m.get("content")]
    conversations[session_id] = simplified[-20:]

    return jsonify({"response": answer})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
