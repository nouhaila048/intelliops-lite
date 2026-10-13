import re

from src.contrat import Evenement, SEVERITES

_SECRET_RE = re.compile(
    r"\b(password|passwd|token|secret|api_key)(\s*[=:]\s*)\S+",
    re.IGNORECASE,
)


def masquer_secrets(texte: str) -> str:
    return _SECRET_RE.sub(r"\1\2[SECRET]", texte)


def normaliser_docker(ligne: str, numero: int,
                      environment: str = "production") -> Evenement:
    raise NotImplementedError


def normaliser_trivy(rapport: dict, numero: int,
                     environment: str = "production") -> Evenement:
    raise NotImplementedError
