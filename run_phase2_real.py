import asyncio
from phase2_refinement_validation.phase2_backend import run_phase2

async def main():
    print("========== REAL PHASE 2 EXECUTION ==========")
    result = await run_phase2()
    print("========== PHASE 2 RETURN ==========")
    print("RETURN:", result)

asyncio.run(main())
