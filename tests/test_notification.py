import unittest
from src.contrat import Analyse, Evenement
from src.notification import choisir_canal, notifier, rediger

def exemple(sensible=True, criticite="CRITICAL"):
    e = Evenement("EVT-00125", "2026-10-05T10:02:11Z", "DOCKER", "backend",
                  "production", "CONTAINER_RESTART", "HIGH",
                  "OOMKilled restarts=14")
    a = Analyse("EVT-00125", criticite, "Limite mémoire", "Redémarrer backend",
                sensible, ["DOCKER"])
    return e, a


class TestNotification(unittest.TestCase):
    # --- choisir_canal ---
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITICAL"), "TEAMS")
        self.assertEqual(choisir_canal("HIGH"), "TEAMS")
        self.assertEqual(choisir_canal("MEDIUM"), "EMAIL")
        self.assertEqual(choisir_canal("LOW"), "DASHBOARD")

    def test_canal_invalide(self):
        with self.assertRaises(ValueError):
            choisir_canal("INCONNU")

    # --- rediger ---
    def test_rediger_format(self):
        e, a = exemple()
        attendu = ("[CRITICAL] Service : backend\n"
                   "Incident : OOMKilled restarts=14\n"
                   "Cause probable : Limite mémoire\n"
                   "Action : Redémarrer backend\n"
                   "Sources : DOCKER")
        self.assertEqual(rediger(e, a), attendu)
        self.assertEqual(len(rediger(e, a).split("\n")), 5)

    def test_rediger_plusieurs_sources(self):
        e, a = exemple()
        a.sources = ["DOCKER", "TRIVY"]
        self.assertTrue(rediger(e, a).endswith("Sources : DOCKER, TRIVY"))

        # --- notifier ---
    def test_notifier(self):
        e, a = exemple()
        journal = []
        notif = notifier(e, a, journal)
        self.assertEqual(notif.event_id, "EVT-00125")
        self.assertEqual(notif.canal, "TEAMS")
        self.assertEqual(notif.destinataire, "equipe-ops")
        self.assertEqual(notif.message, rediger(e, a))
        self.assertEqual(journal, [notif])
        self.assertEqual(e.status, "NOTIFIED")

    def test_notifier_criticite_invalide(self):
        e, a = exemple(criticite="XXX")
        with self.assertRaises(ValueError):
            notifier(e, a, [])

if __name__ == "__main__":
    unittest.main()