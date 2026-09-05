from dataclasses import dataclass

from models.attack_plan import AttackPlan
from models.validation_result import ValidationResult


@dataclass(slots=True)
class RetestCase:

    name: str

    payload: str

    mutation: str


class AdaptiveRetestingEngine:

    """
    Execute adaptive retests for a candidate vulnerability.
    """

    def execute(

        self,

        attack_plan: AttackPlan,

        mutator,

        replay_engine,

    ) -> list[ValidationResult]:

        results = []

        test_cases = mutator.generate(attack_plan)

        for case in test_cases:

            result = replay_engine.replay(

                attack_plan,

                payload=case.payload,

            )

            result.metadata["mutation"] = case.mutation

            result.metadata["test_name"] = case.name

            results.append(result)

        return results