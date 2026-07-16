"""
Client pour l'API REST du Wazuh Manager (port 55000 par défaut).
Documentation officielle : https://documentation.wazuh.com/current/user-manual/api/reference.html
"""
import requests
import urllib3


class WazuhClient:
    def __init__(self, base_url, user, password, verify_ssl=False):
        if not base_url:
            raise ValueError("WAZUH_API_URL manquant dans la configuration (.env)")
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._token = None

    # -- Authentification -------------------------------------------------

    def _authenticate(self):
        resp = requests.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.user, self.password),
            verify=self.verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        return self._token

    def _headers(self):
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def _get(self, path, params=None):
        resp = requests.get(
            f"{self.base_url}{path}",
            headers=self._headers(),
            params=params,
            verify=self.verify_ssl,
            timeout=15,
        )
        if resp.status_code == 401:
            # Token expiré : on ré-authentifie une fois
            self._authenticate()
            resp = requests.get(
                f"{self.base_url}{path}",
                headers=self._headers(),
                params=params,
                verify=self.verify_ssl,
                timeout=15,
            )
        resp.raise_for_status()
        return resp.json()

    # -- a. État du Manager -------------------------------------------------

    def manager_status(self):
        status = self._get("/manager/status")["data"]["affected_items"][0]
        info = self._get("/manager/info")["data"]["affected_items"][0]
        return {
            "processus_daemon": status,
            "version": info.get("version"),
            "date_compilation": info.get("compilation_date"),
            "date_demarrage": info.get("last_keepalive", info.get("start_time")),
        }

    # -- b. Agents et leurs états --------------------------------------------

    def list_agents(self, status=None, os_platform=None, limit=200):
        """status: active | disconnected | pending | never_connected
        os_platform: ex. 'windows', 'ubuntu', 'debian'..."""
        params = {"limit": limit}
        filters = []
        if status:
            filters.append(f"status={status}")
        if os_platform:
            filters.append(f"os.platform={os_platform}")
        if filters:
            params["q"] = ";".join(filters)

        items = self._get("/agents", params=params)["data"]["affected_items"]
        agents = []
        for a in items:
            agents.append(
                {
                    "id": a.get("id"),
                    "nom": a.get("name"),
                    "ip": a.get("ip"),
                    "os": (a.get("os") or {}).get("name"),
                    "statut": a.get("status"),
                    "derniere_connexion": a.get("lastKeepAlive"),
                }
            )
        return agents

    # -- d. SCA (Security Configuration Assessment) --------------------------

    def sca_summary(self, agent_id):
        policies = self._get(f"/sca/{agent_id}")["data"]["affected_items"]
        return [
            {
                "policy_id": p.get("policy_id"),
                "politique": p.get("name"),
                "score_pct": p.get("score"),
                "total_checks": p.get("total_checks"),
                "reussis": p.get("pass"),
                "echoues": p.get("fail"),
            }
            for p in policies
        ]

    def sca_failed_checks(self, agent_id, policy_id, limit=50):
        checks = self._get(
            f"/sca/{agent_id}/checks/{policy_id}",
            params={"result": "failed", "limit": limit},
        )["data"]["affected_items"]
        return [
            {
                "titre": c.get("title"),
                "description": c.get("description"),
                "remediation": c.get("remediation"),
                "rationale": c.get("rationale"),
            }
            for c in checks
        ]
