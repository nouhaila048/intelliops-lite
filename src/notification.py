from src.contrat import Analyse, Evenement, Notification


def choisir_canal(criticite: str) -> str:
    canaux = {
        "CRITICAL": "TEAMS",
        "HIGH": "TEAMS",
        "MEDIUM": "EMAIL",
        "LOW": "DASHBOARD",
    }
    if criticite not in canaux:
        raise ValueError(f"Criticité inconnue : {criticite}")
    return canaux[criticite]


def rediger(evt: Evenement, analyse: Analyse) -> str:
    return "\n".join([
        f"[{analyse.criticite}] Service : {evt.component}",
        f"Incident : {evt.message}",
        f"Cause probable : {analyse.cause_probable}",
        f"Action : {analyse.action_recommandee}",
        f"Sources : {', '.join(analyse.sources)}",
    ])


def notifier(evt: Evenement, analyse: Analyse, journal: list) -> Notification:
    notif = Notification(
        event_id=evt.id,
        canal=choisir_canal(analyse.criticite),
        destinataire="equipe-ops",
        message=rediger(evt, analyse),
    )
    journal.append(notif)
    evt.status = "NOTIFIED"
    return notif


def demander_validation(analyse: Analyse, reponse: str) -> bool:
    if not analyse.sensible:
        return True
    return reponse.strip().lower() in {"o", "oui", "y", "yes"}
