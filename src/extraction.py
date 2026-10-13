import re

from src.contrat import Evenement, SEVERITES

_SECRET_RE = re.compile(
    r"\b(password|passwd|token|secret|api_key)(\s*[=:]\s*)\S+",
    re.IGNORECASE,
)


def masquer_secrets(texte: str) -> str:
    return _SECRET_RE.sub(r"\1\2[SECRET]", texte)


_NIVEAUX = {"ERROR": "HIGH", "WARN": "MEDIUM", "INFO": "LOW"}


def normaliser_docker(ligne: str, numero: int,
                      environment: str = "production") -> Evenement:
    champs = ligne.split(maxsplit=4)
    if len(champs) < 5:
        raise ValueError(f"Ligne Docker invalide : {ligne!r}")
    date, heure, niveau, composant, message = champs
    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=f"{date}T{heure}Z",
        source="DOCKER",
        component=composant,
        environment=environment,
        event_type="CONTAINER_RESTART" if "restarts=" in message else "LOG",
        severity=_NIVEAUX.get(niveau.upper(), "LOW"),
        message=masquer_secrets(message),
    )


def normaliser_trivy(rapport: dict, numero: int,
                     environment: str = "production") -> Evenement:
    raise NotImplementedError
