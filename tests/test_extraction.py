import unittest

from src.extraction import masquer_secrets, normaliser_docker, normaliser_trivy

LIGNE = "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02"
RAPPORT = {"Target": "backend", "VulnerabilityID": "CVE-2026-1234",
           "PkgName": "lib", "InstalledVersion": "1.2.3",
           "Severity": "CRITICAL", "Timestamp": "2026-10-05T10:07:00Z"}


class TestExtraction(unittest.TestCase):
    # --- masquer_secrets
    def test_masquer_secrets(self):
        self.assertEqual(masquer_secrets("login ok password=abc123 user=bob"),
                         "login ok password=[SECRET] user=bob")

    def test_masquer_secrets_casse_et_deux_points(self):
        self.assertEqual(masquer_secrets("TOKEN:xyz Api_Key=k1"),
                         "TOKEN:[SECRET] Api_Key=[SECRET]")

    def test_masquer_secrets_sans_secret(self):
        self.assertEqual(masquer_secrets("health check ok"), "health check ok")

    # --- normaliser_docker
    def test_normaliser_docker(self):
        evt = normaliser_docker(LIGNE, 125)
        self.assertEqual(evt.id, "EVT-00125")
        self.assertEqual(evt.timestamp, "2026-10-05T10:02:11Z")
        self.assertEqual(evt.source, "DOCKER")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.environment, "production")
        self.assertEqual(evt.event_type, "CONTAINER_RESTART")
        self.assertEqual(evt.severity, "HIGH")
        self.assertEqual(evt.status, "NEW")

    def test_docker_warn_log_et_secret(self):
        evt = normaliser_docker(
            "2026-10-05 10:05:40 WARN frontend slow response password=abc123", 2)
        self.assertEqual(evt.severity, "MEDIUM")
        self.assertEqual(evt.event_type, "LOG")
        self.assertEqual(evt.message, "slow response password=[SECRET]")

    def test_docker_info_et_niveau_inconnu(self):
        self.assertEqual(normaliser_docker(
            "2026-10-05 10:09:00 INFO api health ok", 3).severity, "LOW")
        self.assertEqual(normaliser_docker(
            "2026-10-05 10:09:00 DEBUG api health ok", 4).severity, "LOW")

    def test_docker_ligne_invalide(self):
        with self.assertRaises(ValueError):
            normaliser_docker("2026-10-05 10:09:00 INFO api", 5)

    # --- normaliser_trivy
    def test_normaliser_trivy(self):
        evt = normaliser_trivy(RAPPORT, 5)
        self.assertEqual(evt.id, "EVT-00005")
        self.assertEqual(evt.source, "TRIVY")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.event_type, "VULNERABILITY")
        self.assertEqual(evt.severity, "CRITICAL")
        self.assertEqual(evt.message,
                         "Vulnérabilité CVE-2026-1234 détectée dans lib 1.2.3")

    def test_trivy_gravite_minuscule_et_inconnue(self):
        self.assertEqual(normaliser_trivy({**RAPPORT, "Severity": "high"}, 6).severity, "HIGH")
        self.assertEqual(normaliser_trivy({**RAPPORT, "Severity": "???"}, 7).severity, "LOW")

    def test_trivy_cle_manquante(self):
        rapport = dict(RAPPORT)
        del rapport["PkgName"]
        with self.assertRaises(ValueError):
            normaliser_trivy(rapport, 8)


if __name__ == "__main__":
    unittest.main()
