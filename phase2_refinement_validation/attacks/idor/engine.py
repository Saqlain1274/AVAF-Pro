"""
===============================================================================
IDOR Attack Engine
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.attacks.base_workflow_attack import (
    BaseWorkflowAttack,
)

from .identifier_extractor import IdentifierExtractor
from .response_comparator import ResponseComparator
from .access_analyzer import AccessAnalyzer


class IDORAttack(BaseWorkflowAttack):

    id = "idor"

    name = "Insecure Direct Object Reference"

    capability = None

    def __init__(self):

        self.identifier_extractor = IdentifierExtractor()

        self.response_comparator = ResponseComparator()

        self.access_analyzer = AccessAnalyzer()

    def supports(
        self,
        vector,
    ) -> bool:
        parameter_type = str(
            getattr(vector, "parameter_type", "") or ""
        ).strip().lower()
    
        parameter = str(
            getattr(vector, "parameter", "") or ""
        ).strip().lower()
    
        if parameter_type not in {
            "query",
            "form",
            "json",
            "xml",
            "cookie",
            "path",
            "url",
        }:
            return False
    
        identifier_names = {
            "id",
            "uid",
            "user_id",
            "userid",
            "account_id",
            "accountid",
            "customer_id",
            "customerid",
            "order_id",
            "orderid",
            "product_id",
            "productid",
            "item_id",
            "itemid",
            "object_id",
            "objectid",
            "document_id",
            "documentid",
            "file_id",
            "fileid",
            "record_id",
            "recordid",
            "profile_id",
            "profileid",
            "resource_id",
            "resourceid",
        }
    
        return parameter in identifier_names

    def execute(
        self,
        vector,
        context,
    ):

        findings = []

        identifiers = self.identifier_extractor.extract(vector)

        if not identifiers:
            return findings

        for identifier in identifiers:
            
            print(
                f"[TRACE][IDOR][BEFORE_BUILD] "
                f"vector_url={vector.url!r} "
                f"identifier_source={identifier.source!r} "
                f"original={identifier.original_value!r} "
                f"replacement={identifier.replacement_value!r}",
                flush=True,
            )

            prepared_request = context.builder.replace_identifier(
                vector=vector,
                identifier=identifier,
            )
            
            print(
                f"[TRACE][IDOR][AFTER_BUILD] "
                f"vector_url={vector.url!r} "
                f"prepared_url={prepared_request.url!r}",
                flush=True,
            )

            modified_response = context.executor.execute(
                prepared_request
            )

            comparison = self.response_comparator.compare(
                context.original_response,
                modified_response,
            )

            result = self.access_analyzer.analyze(
                vector=vector,
                identifier=identifier,
                comparison=comparison,
                original_response=context.original_response,
                modified_response=modified_response,
            )

            if result is not None:
                findings.append(result)

        return findings