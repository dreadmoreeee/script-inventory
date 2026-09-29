"""Inventory every script a page runs: party, vendor, size, SRI, libraries, advisories."""

__version__ = "1.0.0"

from .analyze import PageReport, Script, build_report  # noqa: E402
from .sri import check_integrity, sri_hash  # noqa: E402

__all__ = ["PageReport", "Script", "build_report", "check_integrity", "sri_hash", "__version__"]
