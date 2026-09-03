# Chatbot SOC basé sur Wazuh

Chatbot conversationnel destiné aux analystes SOC, capable d'interroger l'API REST
du Wazuh Manager et le Wazuh Indexer (OpenSearch) pour répondre en langage naturel.

## Architecture

```
Utilisateur (interface web)
        │
Serveur chatbot (Flask, app.py)
        │
Agent IA (agent.py) ── function calling ── OpenRouter (Qwen)
        │
        ├── API Wazuh (wazuh_client.py)   → Manager, Agents, SCA
        └── Wazuh Indexer (wazuh_indexer.py) → Alertes, MITRE, Vulnérabilités
```

L'agent reçoit le message de l'utilisateur, décide via le LLM (Qwen, via OpenRouter)
quel(s) outil(s) Wazuh appeler, exécute les appels réels, puis reformule une réponse
en français à partir des données obtenues. Aucune donnée n'est inventée : si un outil
échoue, l'agent le signale explicitement.

## Fonctionnalités couvertes

| # | Fonctionnalité | Outil agent | Source |
|---|---|---|---|
| a | État du Manager Wazuh | `get_manager_status` | API Wazuh |
| b | Liste des agents et statuts | `list_agents` | API Wazuh |
| c | Résumé MITRE ATT&CK | `get_mitre_summary` | Wazuh Indexer |
| d | Conformité SCA | `get_sca_summary`, `get_sca_failed_checks` | API Wazuh |
| e | Hygiène IT / vulnérabilités | `get_it_hygiene` | Wazuh Indexer |
| f | Top événements critiques | `get_top_events` | Wazuh Indexer |

## Installation

```bash
cd wazuh-chatbot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Éditer `.env` avec :
- l'URL de ton Manager Wazuh (`WAZUH_API_URL`, port 55000) et les identifiants d'un
  utilisateur ayant les droits API (par défaut `wazuh-wui` — voir
  `/var/ossec/api/configuration/api.yaml` ou créer un utilisateur dédié via
  `/security/users`) ;
- l'URL de ton Wazuh Indexer (`WAZUH_INDEXER_URL`, port 9200) et les identifiants
  OpenSearch (par défaut `admin`) ;
- ta clé API OpenRouter (`OPENROUTER_API_KEY`), obtenue sur https://openrouter.ai/keys.

## Lancement

```bash
python app.py
```

L'interface est disponible sur `http://localhost:5000`.

## Vérification rapide de la connexion Wazuh

Avant de lancer le chatbot, tu peux valider tes identifiants manuellement :

```bash
# Authentification API Manager
curl -u wazuh-wui:changeme -k -X POST https://<IP_MANAGER>:55000/security/user/authenticate

# Test Indexer
curl -u admin:changeme -k https://<IP_MANAGER>:9200/_cat/indices?v
```

Si ces deux commandes échouent, corrige d'abord la configuration réseau/identifiants
avant de lancer `app.py` — le chatbot renverra sinon des erreurs d'authentification
lisibles dans les réponses ("Erreur agent : ...").

