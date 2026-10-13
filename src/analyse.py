from src.contrat import Analyse, Evenement



def est_doublon(evt: Evenement, deja_vus: set) -> bool:
    cle = (evt.source, evt.component, evt.event_type, evt.message)

    if cle in deja_vus:
        return True

    deja_vus.add(cle)
    return False




def rechercher_runbook(evt: Evenement, base: dict):
    for mot_cle, procedure in base.items():
        if mot_cle.lower() in evt.message.lower():
            return procedure

    return None



def classer(evt: Evenement) -> str:
    raise NotImplementedError


def analyser(evt: Evenement, base: dict) -> Analyse:
    raise NotImplementedError
