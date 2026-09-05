from pathlib import Path

files = [
    "phase2_refinement_validation/models/attack_result.py",
    "phase2_refinement_validation/dispatcher/attack_dispatcher.py",
    "phase2_refinement_validation/engine/attack_engine.py",
    "phase2_refinement_validation/refinment/executor/attack_executor.py",
]

for name in files:
    p = Path(name)
    print("\n" + "=" * 90)
    print(name)
    print("=" * 90)

    if not p.exists():
        print("FILE NOT FOUND")
        continue

    lines = p.read_text(encoding="utf-8").splitlines()

    for i, line in enumerate(lines, 1):
        low = line.lower()

        if any(x in low for x in [
            "class attackresult",
            "def execute",
            "except",
            "connectionerror",
            "requestexception",
            "return attack",
            "attackresult(",
            "status",
            "confirmed",
            "verified",
            "evidence",
        ]):
            start = max(1, i - 4)
            end = min(len(lines), i + 12)

            print(f"\n--- lines {start}-{end} ---")
            for n in range(start, end + 1):
                print(f"{n}: {lines[n-1]}")
