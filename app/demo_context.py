from dataclasses import dataclass

@dataclass
class Principal:
    subject: str = "demo-operator"
    tenant: str = "demo-workspace"
    groups: tuple[str, ...] = ("workspace",)    
    admin: bool = True


def principal() -> Principal:
    """Return a demo Principal for the demo context."""
    return Principal()