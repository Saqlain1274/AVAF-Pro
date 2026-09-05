import asyncio
import inspect

from phase2_refinement_validation.phase2_backend import run_phase2

async def main():
    print("=" * 80)
    print("REAL PHASE-2 EXECUTION")
    print("=" * 80)

    result = run_phase2()

    if inspect.isawaitable(result):
        print("run_phase2 returned awaitable -> awaiting it")
        result = await result

    print()
    print("FINAL RETURN TYPE:", type(result).__name__)
    print("FINAL RETURN:", result)

asyncio.run(main())
