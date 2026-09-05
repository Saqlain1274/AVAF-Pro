"""
===============================================================================
AVAF Pro

Form Extractor

Extracts HTML forms.

Responsibilities
----------------
✓ Forms
✓ Inputs
✓ Buttons
✓ Textareas
✓ Selects

Never
-----
✘ Submit Forms
✘ Click Buttons
✘ Execute JavaScript
===============================================================================
"""

from __future__ import annotations

from typing import List

from playwright.async_api import ElementHandle
from playwright.async_api import Page

from ..base_extractor import BaseExtractor
from ..model import (
    ButtonInfo,
    ExtractorResult,
    FormInfo,
    InputField,
    OptionInfo,
    SelectInfo,
    TextAreaInfo,
)


class FormExtractor(BaseExtractor):

    def __init__(self):

        super().__init__()

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    async def extract(
        self,
        page: Page,
    ) -> ExtractorResult:

        self.start()

        try:

            forms = await page.query_selector_all(
                "form"
            )

            self.set_total(len(forms))

            seen = set()

            for form in forms:

                info = await self._extract_form(
                    page,
                    form,
                )

                if info is None:
                    continue

                signature = (

                    info.method,

                    info.action,

                    tuple(

                        (
                            field.name,
                            field.field_type,
                        )

                        for field in info.inputs

                    ),

                )

                if signature in seen:

                    self.duplicate()

                    continue

                seen.add(signature)

                self.add_item(info)

        except Exception as exc:

            self.error(exc)

            self.warning(
                "Unable to extract forms."
            )

        return self.finish()

    # ==========================================================
    # FORM
    # ==========================================================

    async def _extract_form(
        self,
        page: Page,
        form: ElementHandle,
    ) -> FormInfo | None:

        try:

            return FormInfo(

                action=await self._read_action(
                    page,
                    form,
                ),

                method=await self._read_method(
                    form,
                ),

                enctype=await self._read_enctype(
                    form,
                ),

                inputs=await self._extract_inputs(
                    form,
                ),

                buttons=await self._extract_buttons(
                    form,
                ),

                textareas=await self._extract_textareas(
                    form,
                ),

                selects=await self._extract_selects(
                    form,
                ),

            )

        except Exception as exc:

            self.error(exc)

            return None

    # ==========================================================
    # HELPERS
    # ==========================================================

    async def _read_action(
        self,
        page: Page,
        form: ElementHandle,
    ) -> str:

        return (

            await form.get_attribute(
                "action"
            )

            or

            page.url

        )

    async def _read_method(
        self,
        form: ElementHandle,
    ) -> str:

        return (

            await form.get_attribute(
                "method"
            )

            or

            "GET"

        ).upper()

    async def _read_enctype(
        self,
        form: ElementHandle,
    ) -> str:

        return (

            await form.get_attribute(
                "enctype"
            )

            or

            "application/x-www-form-urlencoded"

        )

    # ==========================================================
    # INPUTS
    # ==========================================================

    async def _extract_inputs(
        self,
        form: ElementHandle,
    ) -> List[InputField]:

        results = []

        for element in await form.query_selector_all(
            "input"
        ):

            try:

                results.append(

                    InputField(

                        name=await element.get_attribute("name") or "",

                        field_type=(

                            await element.get_attribute("type")

                            or

                            "text"

                        ).lower(),

                        value=await element.get_attribute("value") or "",

                        placeholder=await element.get_attribute("placeholder") or "",

                        required=await element.get_attribute("required") is not None,

                        autocomplete=await element.get_attribute("autocomplete") or "",

                        disabled=await element.get_attribute("disabled") is not None,

                        readonly=await element.get_attribute("readonly") is not None,

                    )

                )

            except Exception:

                continue

        return results

    # ==========================================================
    # BUTTONS
    # ==========================================================

    async def _extract_buttons(
        self,
        form: ElementHandle,
    ) -> List[ButtonInfo]:

        results = []

        for element in await form.query_selector_all(
            "button"
        ):

            try:

                results.append(

                    ButtonInfo(

                        text=(

                            await element.inner_text()

                        ).strip(),

                        button_type=await element.get_attribute("type") or "submit",

                        name=await element.get_attribute("name") or "",

                        value=await element.get_attribute("value") or "",

                    )

                )

            except Exception:

                continue

        return results

    # ==========================================================
    # TEXTAREAS
    # ==========================================================

    async def _extract_textareas(
        self,
        form: ElementHandle,
    ) -> List[TextAreaInfo]:

        results = []

        for element in await form.query_selector_all(
            "textarea"
        ):

            try:

                results.append(

                    TextAreaInfo(

                        name=await element.get_attribute("name") or "",

                        value=await element.input_value(),

                        placeholder=await element.get_attribute("placeholder") or "",

                    )

                )

            except Exception:

                continue

        return results

    # ==========================================================
    # SELECTS
    # ==========================================================

    async def _extract_selects(
        self,
        form: ElementHandle,
    ) -> List[SelectInfo]:

        results = []

        for select in await form.query_selector_all(
            "select"
        ):

            options = []

            for option in await select.query_selector_all(
                "option"
            ):

                try:

                    options.append(

                        OptionInfo(

                            text=(

                                await option.inner_text()

                            ).strip(),

                            value=await option.get_attribute("value") or "",

                            selected=await option.get_attribute("selected") is not None,

                        )

                    )

                except Exception:

                    continue

            results.append(

                SelectInfo(

                    name=await select.get_attribute("name") or "",

                    multiple=await select.get_attribute("multiple") is not None,

                    options=options,

                )

            )

        return results