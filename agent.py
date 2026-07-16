"""
Agent IA du chatbot : appelle Qwen via OpenRouter avec function-calling,
exécute les outils Wazuh nécessaires, puis reformule la réponse en français.
"""
import os
import json
import requests

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = """Tu es l'assistant IA d'un SOC (Security Operations Center) supervisé par Wazuh.
Tu réponds toujours en français, de façon claire, concise et professionnelle, comme si tu t'adressais à un analyste SOC.

Règles impératives :
- Utilise systématiquement les outils fournis pour aller chercher les données réelles avant de répondre.
- Ne jamais inventer un agent, une CVE, un score ou un événement : si l'information n'est pas disponible via un outil, dis-le.
- Si un outil renvoie une erreur, explique le problème clairement (ex: agent introuvable, API injoignable) plutôt que d'improviser.
- Structure les réponses avec des listes ou petits tableaux Markdown quand c'est pertinent (agents, CVE, alertes).
- Termine par une phrase de synthèse ou une recommandation quand c'est utile à un analyste.
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_manager_status",
            "description": "Récupère l'état du Manager Wazuh (daemons actifs, version, uptime).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_agents",
            "description": "Liste les agents Wazuh enregistrés avec IP, OS, statut et dernière connexion.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["active", "disconnected", "pending", "never_connected"],
                        "description": "Filtrer par statut (optionnel)",
                    },
                    "os_platform": {
                        "type": "string",
                        "description": "Filtrer par plateforme OS, ex: windows, ubuntu, debian (optionnel)",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_mitre_summary",
            "description": "Résume les tactiques et techniques MITRE ATT&CK détectées récemment, et les agents concernés.",
            "parameters": {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "description": "Fenêtre temporelle en jours (défaut 7)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_sca_summary",
            "description": "Donne le score de conformité SCA (Security Configuration Assessment) d'un agent, par politique.",
            "parameters": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID de l'agent Wazuh"}},
                "required": ["agent_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_sca_failed_checks",
            "description": "Liste les contrôles SCA échoués pour un agent et une politique donnés, avec recommandations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string"},
                    "policy_id": {"type": "string", "description": "Identifiant de la politique SCA (obtenu via get_sca_summary)"},
                },
                "required": ["agent_id", "policy_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_it_hygiene",
            "description": "Évalue l'hygiène IT d'un agent : vulnérabilités détectées, sévérité, paquets concernés.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_name": {"type": "string", "description": "Nom de l'agent Wazuh"},
                    "severity": {
                        "type": "string",
                        "enum": ["Low", "Medium", "High", "Critical"],
                        "description": "Filtrer par sévérité (optionnel)",
                    },
                },
                "required": ["agent_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_top_events",
            "description": "Retourne les N événements de sécurité les plus critiques sur une période récente.",
            "parameters": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Nombre d'événements (défaut 5)"},
                    "hours": {"type": "integer", "description": "Fenêtre temporelle en heures (défaut 24)"},
                },
            },
        },
    },
]


class WazuhChatAgent:
    def __init__(self, wazuh_client, wazuh_indexer, model=None, api_key=None):
        self.wc = wazuh_client
        self.wi = wazuh_indexer
        self.model = model or os.getenv("OPENROUTER_MODEL", "qwen/qwen-2.5-72b-instruct")
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")

    def _call_llm(self, messages):
        if not self.api_key:
            raise RuntimeError("OPENROUTER_API_KEY manquant dans la configuration (.env)")
        resp = requests.post(
            OPENROUTER_URL,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={"model": self.model, "messages": messages, "tools": TOOLS, "tool_choice": "auto"},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]

    def _execute_tool(self, name, args):
        try:
            if name == "get_manager_status":
                return self.wc.manager_status()
            if name == "list_agents":
                return self.wc.list_agents(status=args.get("status"), os_platform=args.get("os_platform"))
            if name == "get_mitre_summary":
                return self.wi.mitre_summary(days=args.get("days", 7))
            if name == "get_sca_summary":
                return self.wc.sca_summary(args["agent_id"])
            if name == "get_sca_failed_checks":
                return self.wc.sca_failed_checks(args["agent_id"], args["policy_id"])
            if name == "get_it_hygiene":
                return self.wi.vulnerabilities(args["agent_name"], severity=args.get("severity"))
            if name == "get_top_events":
                return self.wi.top_events(count=args.get("count", 5), hours=args.get("hours", 24))
            return {"erreur": f"Outil inconnu: {name}"}
        except Exception as e:
            return {"erreur": str(e)}

    def chat(self, history, user_message, max_tool_rounds=5):
        """history: liste de messages {role, content} (user/assistant uniquement).
        Retourne (réponse_texte, messages_complets_hors_system)."""
        messages = [{"role": "system", "content": SYSTEM_PROMPT}] + list(history) + [
            {"role": "user", "content": user_message}
        ]

        for _ in range(max_tool_rounds):
            message = self._call_llm(messages)
            messages.append(message)
            tool_calls = message.get("tool_calls")
            if not tool_calls:
                return message.get("content", "").strip(), messages[1:]

            for tc in tool_calls:
                fn_name = tc["function"]["name"]
                try:
                    fn_args = json.loads(tc["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    fn_args = {}
                result = self._execute_tool(fn_name, fn_args)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": json.dumps(result, ensure_ascii=False, default=str),
                    }
                )

        return (
            "Je n'ai pas réussi à obtenir une réponse complète après plusieurs appels aux outils Wazuh. "
            "Peux-tu reformuler ta question ?",
            messages[1:],
        )
