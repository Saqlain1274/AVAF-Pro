from dataclasses import dataclass, field
from typing import Any


@dataclass(order=True)
class BehaviorTask:

    priority: float

    action: str = field(compare=False)

    selector: str = field(compare=False)

    description: str = field(compare=False)

    element: Any = field(compare=False)

    metadata: dict = field(

        default_factory=dict,

        compare=False,

    )

    explored: bool = field(

        default=False,

        compare=False,

    )