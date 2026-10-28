"""ICARUS — Modular intelligence framework for structured data analysis."""

from icarus.core.pipeline import Pipeline, create_default_pipeline
from icarus.core.query import IcarusQuery
from icarus.core.schema import initialize_database
from icarus.parsers.base import BaseParser

__version__ = "4.0.0b2"

__all__ = [
    "__version__",
    "Pipeline",
    "create_default_pipeline",
    "IcarusQuery",
    "BaseParser",
    "initialize_database",
]
