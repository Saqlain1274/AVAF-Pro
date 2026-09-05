
import asyncio
from playwright.async_api import async_playwright


async def main():
    async with async_playwright() as p:

        print("Launching Chromium...")

        browser = await p.chromium.launch(
            headless=True
        )

        context = await browser.new_context()

        page = await context.new_page()

        print("Navigating...")

        try:
            response = await page.goto(
                "http://testasp.vulnweb.com/",
                wait_until="domcontentloaded",
                timeout=30000,
            )

            print("STATUS:", response.status if response else None)
            print("URL:", page.url)
            print("TITLE:", await page.title())

            html = await page.content()

            print("HTML LENGTH:", len(html))

        except Exception as exc:
            print("PLAYWRIGHT ERROR:")
            print(type(exc).__name__)
            print(str(exc))

        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
