from dataclasses import asdict

from .model import PageResult


def page_result_to_dict(page: PageResult) -> dict:
    """
    Convert a PageResult into a JSON-serializable dictionary.
    """
    return asdict(page)