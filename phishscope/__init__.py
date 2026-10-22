"""phishscope: static phishing analysis for .eml files."""

__version__ = "1.0.0"

from .analyzer import Report, analyze_bytes, analyze_file  # noqa: E402,F401
