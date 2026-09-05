"""
===============================================================================
Attack Registry

Central registry for all supported attack modules.

The dispatcher asks this registry for an attack implementation instead of
hardcoding knowledge of SQLi, XSS, LFI, etc.
===============================================================================
"""

from __future__ import annotations

from typing import Dict
from typing import Iterable
from typing import Optional

from phase2_refinement_validation.attacks.base_attack import BaseAttack


class AttackRegistry:
    """
    Stores all registered attack modules.
    """

    def __init__(self) -> None:
        self._attacks: Dict[str, BaseAttack] = {}
        self._locked = False

    def register(self, attack: BaseAttack) -> None:
        """
        Register an attack implementation.
        """
        if self._locked:
           raise RuntimeError("Attack registry is locked.")
        attack_id = attack.id.lower()

        if attack_id in self._attacks:
            raise ValueError(
                f"Attack '{attack_id}' is already registered."
            )

        self._attacks[attack_id] = attack

    def register_many(
        self,
        *attacks: BaseAttack,
    ) -> None:
        """
        Register multiple attack modules.
        """

        for attack in attacks:
            self.register(attack)

    def get(
        self,
        attack_id : str,
    ) -> BaseAttack:
        """
        Retrieve an attack implementation by name.
        """

        try:
            return self._attacks[attack_id.lower()]

        except KeyError as exc:
            raise ValueError(
                f"Unknown attack '{attack_id}'."
            ) from exc

    def find(
        self,
        attack_name: str,
    ) -> Optional[BaseAttack]:
        """
        Retrieve an attack implementation if present.
        """

        return self._attacks.get(
            attack_name.lower()
        )

    def all(self) -> Iterable[BaseAttack]:
        """
        Return all registered attacks.
        """

        return self._attacks.values()

    def supports(
        self,
        attack_name: str,
    ) -> bool:
        """
        Check whether an attack is registered.
        """

        return attack_name.lower() in self._attacks

    def __len__(self) -> int:
        return len(self._attacks)

    def __contains__(
        self,
        attack_name: str,
    ) -> bool:
        return self.supports(attack_name)
    
    def lock(self) -> None:
       self._locked = True