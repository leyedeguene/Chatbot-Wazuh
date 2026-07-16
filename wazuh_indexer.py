"""
Client pour le Wazuh Indexer (OpenSearch, port 9200 par défaut).
Interroge directement les index wazuh-alerts-* et wazuh-states-vulnerabilities-*.
"""
import requests
import urllib3


class WazuhIndexer:
    def __init__(self, base_url, user, password, verify_ssl=False):
        if not base_url:
            raise ValueError("WAZUH_INDEXER_URL manquant dans la configuration (.env)")
        self.base_url = base_url.rstrip("/")
        self.auth = (user, password)
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _search(self, index, body):
        resp = requests.post(
            f"{self.base_url}/{index}/_search",
            auth=self.auth,
            json=body,
            verify=self.verify_ssl,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    # -- f. Top événements de sécurité ---------------------------------------

    def top_events(self, count=5, hours=24):
        body = {
            "size": count,
            "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "sort": [{"rule.level": {"order": "desc"}}, {"@timestamp": {"order": "desc"}}],
        }
        hits = self._search("wazuh-alerts-*", body).get("hits", {}).get("hits", [])
        return [
            {
                "horodatage": h["_source"].get("@timestamp"),
                "agent": (h["_source"].get("agent") or {}).get("name"),
                "niveau": (h["_source"].get("rule") or {}).get("level"),
                "description": (h["_source"].get("rule") or {}).get("description"),
                "mitre_technique": ((h["_source"].get("rule") or {}).get("mitre") or {}).get("technique"),
            }
            for h in hits
        ]

    # -- c. Résumé MITRE ATT&CK ---------------------------------------------

    def mitre_summary(self, days=7):
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
            "aggs": {
                "tactiques": {"terms": {"field": "rule.mitre.tactic", "size": 10}},
                "techniques": {"terms": {"field": "rule.mitre.technique", "size": 10}},
                "agents_concernes": {"terms": {"field": "agent.name", "size": 10}},
            },
        }
        aggs = self._search("wazuh-alerts-*", body).get("aggregations", {})
        return {
            "periode_jours": days,
            "tactiques_frequentes": [
                {"tactique": b["key"], "occurrences": b["doc_count"]}
                for b in aggs.get("tactiques", {}).get("buckets", [])
            ],
            "techniques_frequentes": [
                {"technique": b["key"], "occurrences": b["doc_count"]}
                for b in aggs.get("techniques", {}).get("buckets", [])
            ],
            "agents_concernes": [
                {"agent": b["key"], "occurrences": b["doc_count"]}
                for b in aggs.get("agents_concernes", {}).get("buckets", [])
            ],
        }

    # -- e. Hygiène IT / vulnérabilités ---------------------------------------

    def vulnerabilities(self, agent_name, severity=None, limit=50):
        must = [{"match": {"agent.name": agent_name}}]
        if severity:
            must.append({"match": {"vulnerability.severity": severity}})
        body = {
            "size": limit,
            "query": {"bool": {"must": must}},
            "sort": [{"vulnerability.score.base": {"order": "desc"}}],
        }
        hits = self._search("wazuh-states-vulnerabilities-*", body).get("hits", {}).get("hits", [])
        return [
            {
                "cve": (h["_source"].get("vulnerability") or {}).get("id"),
                "severite": (h["_source"].get("vulnerability") or {}).get("severity"),
                "score_cvss": ((h["_source"].get("vulnerability") or {}).get("score") or {}).get("base"),
                "paquet": (h["_source"].get("package") or {}).get("name"),
                "version_installee": (h["_source"].get("package") or {}).get("version"),
            }
            for h in hits
        ]
