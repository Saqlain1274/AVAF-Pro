from phase2_refinement_validation.bootstrap import create_attack_registry
from phase2_refinement_validation.phase2_backend import _load_phase1_vectors

registry = create_attack_registry()
vectors = _load_phase1_vectors()

for i, vector in enumerate(vectors, 1):
    supported = [
        attack.id
        for attack in registry.all()
        if attack.supports(vector)
    ]

    print(
        f"VECTOR {i}: "
        f"{vector.method} "
        f"{vector.url} "
        f"PARAM={vector.parameter!r} "
        f"-> {supported}"
    )
