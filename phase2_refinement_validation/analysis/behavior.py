"""
===============================================================================
AVAF Pro

Behavior Analysis Engine

Purpose
-------
Analyzes how the target server behaves after replaying an attack.

This module does NOT detect vulnerabilities.

Instead it extracts behavioural characteristics that are later consumed by:

    • Statistics Analysis
    • Rule Engine
    • ML Engine
    • Refinement Engine

===============================================================================
"""

from __future__ import annotations

from difflib import SequenceMatcher

from models.http_exchange import HTTPExchange


class BehaviorAnalyzer:

    """
    Server Behaviour Analysis Engine
    """

    # ==================================================================
    # PUBLIC
    # ==================================================================

    def analyze(

        self,

        baseline: HTTPExchange,

        replay: HTTPExchange,

    ) -> dict:

        report = {

            "status_changed": False,

            "body_changed": False,

            "headers_changed": False,

            "cookies_changed": False,

            "redirect_changed": False,

            "content_type_changed": False,

            "encoding_changed": False,

            "timing_changed": False,

            "length_changed": False,

            "length_delta": 0,

            "similarity": 100.0,

            "response_time_delta": 0.0,

            "response_growth": 0.0,

            "features": []

        }

        report["status_changed"] = self._status_changed(
            baseline,
            replay,
        )

        report["body_changed"] = self._body_changed(
            baseline,
            replay,
        )

        report["headers_changed"] = self._headers_changed(
            baseline,
            replay,
        )

        report["cookies_changed"] = self._cookies_changed(
            baseline,
            replay,
        )

        report["redirect_changed"] = self._redirect_changed(
            baseline,
            replay,
        )

        report["content_type_changed"] = self._content_type_changed(
            baseline,
            replay,
        )

        report["encoding_changed"] = self._encoding_changed(
            baseline,
            replay,
        )

        report["timing_changed"] = self._timing_changed(
            baseline,
            replay,
        )

        report["length_delta"] = self._length_delta(
            baseline,
            replay,
        )

        report["length_changed"] = report["length_delta"] != 0

        report["similarity"] = self._similarity(
            baseline,
            replay,
        )

        report["response_time_delta"] = abs(

            replay.response.elapsed

            -

            baseline.response.elapsed

        )

        report["response_growth"] = self._growth(
            baseline,
            replay,
        )

        report["features"] = self._extract_features(
            report
        )

        return report

    # ==================================================================
    # PRIVATE
    # ==================================================================

    def _status_changed(self, baseline, replay):

        return baseline.response.status != replay.response.status

    def _body_changed(self, baseline, replay):

        return baseline.response.body != replay.response.body

    def _headers_changed(self, baseline, replay):

        return baseline.response.headers != replay.response.headers

    def _cookies_changed(self, baseline, replay):

        return baseline.response.cookies != replay.response.cookies

    def _redirect_changed(self, baseline, replay):

        return baseline.response.url != replay.response.url

    def _content_type_changed(self, baseline, replay):

        return (

            baseline.response.headers.get("Content-Type")

            !=

            replay.response.headers.get("Content-Type")

        )

    def _encoding_changed(self, baseline, replay):

        return (

            baseline.response.encoding

            !=

            replay.response.encoding

        )

    def _timing_changed(self, baseline, replay):

        return abs(

            replay.response.elapsed

            -

            baseline.response.elapsed

        ) > 1

    def _length_delta(self, baseline, replay):

        return abs(

            len(replay.response.body)

            -

            len(baseline.response.body)

        )

    def _similarity(self, baseline, replay):

        return round(

            SequenceMatcher(

                None,

                baseline.response.body,

                replay.response.body,

            ).ratio() * 100,

            2,

        )

    def _growth(self, baseline, replay):

        old = len(baseline.response.body)

        new = len(replay.response.body)

        if old == 0:

            return 0.0

        return round(

            ((new - old) / old) * 100,

            2,

        )

    def _extract_features(self, report):

        features = []

        if report["status_changed"]:

            features.append("STATUS_CHANGED")

        if report["body_changed"]:

            features.append("BODY_CHANGED")

        if report["timing_changed"]:

            features.append("TIME_DELAY")

        if report["headers_changed"]:

            features.append("HEADERS_CHANGED")

        if report["cookies_changed"]:

            features.append("COOKIES_CHANGED")

        if report["redirect_changed"]:

            features.append("REDIRECT_CHANGED")

        if report["similarity"] < 30:

            features.append("VERY_LOW_SIMILARITY")

        elif report["similarity"] < 60:

            features.append("LOW_SIMILARITY")

        elif report["similarity"] < 80:

            features.append("MEDIUM_SIMILARITY")

        if report["response_growth"] > 50:

            features.append("RESPONSE_GROWTH")

        return features