import asyncio
from playwright.async_api import async_playwright


async def main():

    async with async_playwright() as p:

        print("[1] Starting Chromium...")

        browser = await p.chromium.launch(
            headless=False
        )

        print("[2] Browser started")

        page = await browser.new_page()

        print("[3] New page created")

        page.on(
            "framenavigated",
            lambda frame: print(f"[FRAME] {frame.url}")
        )

        try:

            print("[4] Before goto")

            response = await page.goto(
                "https://example.com",
                wait_until="domcontentloaded",
                timeout=60000
            )

            print("[5] Navigation finished")

            print("Response :", response.status if response else None)
            print("URL      :", page.url)
            print("Title    :", await page.title())

        except Exception as e:

            print("[ERROR]", repr(e))
            print("Current URL:", page.url)

        print("[6] Browser will stay open for 20 seconds")

        await asyncio.sleep(20)

        await browser.close()

        print("[7] Browser closed")


asyncio.run(main())