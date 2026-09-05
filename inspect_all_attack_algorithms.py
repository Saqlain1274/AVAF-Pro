from pathlib import Path

root = Path("phase2_refinement_validation/attacks")

for engine in sorted(root.rglob("engine.py")):
    print("\n" + "=" * 100)
    print(engine)
    print("=" * 100)

    lines = engine.read_text(encoding="utf-8").splitlines()

    for i, line in enumerate(lines, 1):
        low = line.lower()

        if any(k in low for k in [
            "class ",
            "def supports",
            "def generate_payloads",
            "def execute",
            "detector",
            "payload",
            "attackresult",
            "evidence",
            "indicator",
            "success",
            "confidence",
        ]):
            start = max(1, i - 2)
            end = min(len(lines), i + 8)

            print(f"\n--- lines {start}-{end} ---")

            for n in range(start, end + 1):
                print(f"{n}: {lines[n-1]}")

print("\n" + "=" * 100)
print("DETECTORS")
print("=" * 100)

for detector in sorted(root.rglob("detector.py")):
    print("\n" + "=" * 100)
    print(detector)
    print("=" * 100)

    lines = detector.read_text(encoding="utf-8").splitlines()

    for i, line in enumerate(lines, 1):
        low = line.lower()

        if any(k in low for k in [
            "class ",
            "def ",
            "success",
            "evidence",
            "indicator",
            "confidence",
            "return",
            "response",
        ]):
            start = max(1, i - 2)
            end = min(len(lines), i + 8)

            print(f"\n--- lines {start}-{end} ---")

            for n in range(start, end + 1):
                print(f"{n}: {lines[n-1]}")
