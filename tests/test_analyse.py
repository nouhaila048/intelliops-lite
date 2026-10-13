
import unittest

from src.analyse import analyser, classer, est_doublon, rechercher_runbook
from src.contrat import RUNBOOKS, Evenement


def evt(event_type="LOG", severity="LOW", message="ok", component="backend"):
    return Evenement(
        "EVT-00001",
        "2026-10-05T10:00:00Z",
        "DOCKER",
        component,
        "production",
        event_type,
        severity,
        message
    )


class TestAnalyse(unittest.TestCase):

    def test_doublon(self):
        vus = set()
        self.assertFalse(est_doublon(evt(message="a"), vus))
        self.assertTrue(est_doublon(evt(message="a"), vus))

    def test_doublon_composant_different(self):
        vus = set()
        self.assertFalse(est_doublon(evt(component="backend"), vus))
        self.assertFalse(est_doublon(evt(component="frontend"), vus))

    def test_rechercher_runbook(self):
        e = evt(message="OOMKilled restarts=14")
        self.assertEqual(
            rechercher_runbook(e, RUNBOOKS),
            RUNBOOKS["OOMKilled"]
        )

    def test_runbook_insensible_casse(self):
        e = evt(message="oomkilled")
        self.assertEqual(
            rechercher_runbook(e, RUNBOOKS),
            RUNBOOKS["OOMKilled"]
        )

    def test_runbook_inconnu(self):
        e = evt(message="incident inconnu")
        self.assertIsNone(rechercher_runbook(e, RUNBOOKS))

    def test_classer_redemarrages(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_seuil_10(self):
        e = evt("CONTAINER_RESTART", "HIGH", "restarts=10")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_redemarrages_faibles(self):
        e = evt("CONTAINER_RESTART", "HIGH", "restarts=3")
        self.assertEqual(classer(e), "MEDIUM")

    def test_classer_vulnerabilite(self):
        e = evt("VULNERABILITY", "CRITICAL", "CVE-2026-1234")
        self.assertEqual(classer(e), "HIGH")

    def test_classer_log(self):
        e = evt("LOG", "LOW")
        self.assertEqual(classer(e), "LOW")

    def test_analyser_redemarrage(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")

        resultat = analyser(e, RUNBOOKS)

        self.assertEqual(resultat.event_id, e.id)
        self.assertEqual(resultat.criticite, "CRITICAL")
        self.assertEqual(resultat.cause_probable, RUNBOOKS["OOMKilled"])
        self.assertEqual(resultat.action_recommandee, "Redémarrer backend")
        self.assertTrue(resultat.sensible)
        self.assertEqual(resultat.sources, ["DOCKER"])
        self.assertEqual(e.status, "ANALYSED")

    def test_analyser_vulnerabilite(self):
        e = evt("VULNERABILITY", "CRITICAL", "CVE-2026-1234")

        resultat = analyser(e, RUNBOOKS)

        self.assertEqual(resultat.criticite, "HIGH")
        self.assertEqual(
            resultat.action_recommandee,
            "Mettre à jour la dépendance"
        )
        self.assertTrue(resultat.sensible)

    def test_analyser_inconnu(self):
        e = evt("LOG", "LOW", "incident inconnu")

        resultat = analyser(e, RUNBOOKS)

        self.assertEqual(
            resultat.cause_probable,
            "Cause inconnue : analyse manuelle requise"
        )
        self.assertEqual(resultat.action_recommandee, "Consulter les logs")
        self.assertFalse(resultat.sensible)


if __name__ == "__main__":
    unittest.main()
