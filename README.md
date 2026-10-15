# Chatbot SOC basé sur Wazuh

Ce projet vise à mettre en place un chatbot conversationnel destiné aux analystes SOC, capable d'interroger l'API REST du Wazuh Manager et le Wazuh Indexer (OpenSearch) pour répondre en langage naturel.

L'idée est de transformer une plateforme de supervision riche mais complexe à interroger en un assistant intelligent, capable de synthétiser l'état de la sécurité d'une infrastructure à partir de simples questions.


## Concept

Développer un agent IA qui reçoit les questions de l'analyste, décide via le LLM (Qwen, par OpenRouter) quel(s) outil(s) Wazuh appeler, exécute les appels réels, puis reformule une réponse en français à partir des données obtenues.

Aucune donnée n'est inventée : si un outil échoue, l'agent le signale explicitement.

## Architecture

<img width="491" height="317" alt="image" src="https://github.com/user-attachments/assets/8dbe6325-cf39-49ae-afb2-02ff08e8774b" />

## Fonctionnalités couvertes

| # | Fonctionnalité | Outil agent | Source |
|---|---|---|---|
| a | État du Manager Wazuh | `get_manager_status` | API Wazuh |
| b | Liste des agents et statuts | `list_agents` | API Wazuh |
| c | Résumé MITRE ATT&CK | `get_mitre_summary` | Wazuh Indexer |
| d | Conformité SCA | `get_sca_summary`, `get_sca_failed_checks` | API Wazuh |
| e | Hygiène IT / vulnérabilités | `get_it_hygiene` | Wazuh Indexer |
| f | Top événements critiques | `get_top_events` | Wazuh Indexer |

## Objectif

Faciliter le travail quotidien des analystes SOC en rendant les données de Wazuh accessibles en langage naturel, sans passer par les requêtes manuelles ou la navigation dans plusieurs tableaux de bord.

## Utilité en entreprise

### Pour l'analyste SOC

* Vérifier l'état du Manager et des agents en une question
* Obtenir un résumé des techniques MITRE ATT&CK observées
* Identifier rapidement les événements critiques les plus fréquents

### Pour la conformité

* Consulter les résultats SCA et les contrôles en échec
* Suivre l'hygiène IT et les vulnérabilités détectées sur le parc

### Pour la fiabilité

* Des réponses fondées uniquement sur des appels réels à Wazuh
* Des erreurs signalées explicitement, sans données inventées


## Technologies utilisées & missions

| Composant | Rôle |
| --- | --- |
| **Wazuh Manager (API REST)** | Source des données sur le Manager, les agents et la conformité SCA |
| **Wazuh Indexer (OpenSearch)** | Source des alertes, du MITRE ATT&CK et des vulnérabilités |
| **OpenRouter (Qwen)** | LLM avec function calling pour le choix des outils et la reformulation |
| **Python** | Logique métier : agent, clients Wazuh, appels d'outils |
| **Flask** | Serveur web et interface de chat |


## Installation

```bash
cd wazuh-chatbot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Éditer `.env` avec :

* l'URL du Manager Wazuh (`WAZUH_API_URL`, port 55000) et les identifiants d'un utilisateur ayant les droits API (par défaut `wazuh-wui`, voir `/var/ossec/api/configuration/api.yaml`, ou créer un utilisateur dédié via `/security/users`) ;
* l'URL du Wazuh Indexer (`WAZUH_INDEXER_URL`, port 9200) et les identifiants OpenSearch (par défaut `admin`) ;
* la clé API OpenRouter (`OPENROUTER_API_KEY`), obtenue sur https://openrouter.ai/keys.

## Lancement

```bash
python app.py
```

L'interface est disponible sur `http://localhost:5000`.

## Vérification rapide de la connexion Wazuh

Avant de lancer le chatbot, il est conseillé de valider les identifiants manuellement :

```bash
# Authentification API Manager
curl -u wazuh-wui:changeme -k -X POST https://<IP_MANAGER>:55000/security/user/authenticate

# Test Indexer
curl -u admin:changeme -k https://<IP_MANAGER>:9200/_cat/indices?v
```

Si ces deux commandes échouent, corriger d'abord la configuration réseau et les identifiants avant de lancer `app.py`. Sinon, le chatbot renverra des erreurs d'authentification, lisibles dans les réponses (« Erreur agent : ... »).

<img width="454" height="231" alt="image" src="https://github.com/user-attachments/assets/f0273a7d-5671-4c63-ab73-6142433fff83" />
<img width="450" height="236" alt="image" src="https://github.com/user-attachments/assets/b628c9dc-4aec-4481-b793-a9d519825772" />
<img width="452" height="257" alt="image" src="https://github.com/user-attachments/assets/2e8c39c6-e481-4dcd-b1a1-a87a9175e0e6" />



