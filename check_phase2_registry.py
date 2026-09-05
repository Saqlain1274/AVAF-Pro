from phase2_refinement_validation.bootstrap import create_attack_registry
from phase2_refinement_validation.phase2_backend import _load_phase1_vectors

r = create_attack_registry()
v = _load_phase1_vectors()

print("========== REGISTRY ==========")
print("ATTACK COUNT:", len(r))
print("ATTACKS:")

for a in r.all():
    print(" ", a.id, "|", type(a).__name__)

print()
print("========== VECTOR COMPATIBILITY ==========")
print("VECTOR COUNT:", len(v))

for i, x in enumerate(v, 1):
    print(f"VECTOR {i}: {x.method} {x.url} PARAM={x.parameter!r} TYPE={x.parameter_type!r}")

    for a in r.all():
        try:
            print(f"   {a.id}: {a.supports(x)}")
        except Exception as e:
            print(f"   {a.id}: SUPPORTS_ERROR: {e}")
