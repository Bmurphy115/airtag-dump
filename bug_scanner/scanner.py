"""
Bug scanner for analyzing binary files and firmware dumps.
Searches for known vulnerability patterns in binary data.
"""

import re
from pathlib import Path
from typing import List, Optional, Tuple

from .database import BugDatabase
from .models import Bug, ScanResult


class BugScanner:
    """
    Scanner for detecting bugs/vulnerabilities in binary files.
    Uses pattern matching against a database of known bug signatures.
    """

    def __init__(self, db: BugDatabase):
        """Initialize scanner with a bug database."""
        self.db = db

    def scan_file(
        self,
        file_path: Path,
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
    ) -> List[ScanResult]:
        """
        Scan a binary file for known bug patterns.

        Args:
            file_path: Path to the file to scan
            severity_filter: Only check for bugs of this severity
            category_filter: Only check for bugs of this category

        Returns:
            List of ScanResult objects for detected bugs
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read file contents
        with open(file_path, "rb") as f:
            data = f.read()

        return self.scan_data(
            data,
            source_name=str(file_path),
            severity_filter=severity_filter,
            category_filter=category_filter,
        )

    def scan_data(
        self,
        data: bytes,
        source_name: str = "unknown",
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
    ) -> List[ScanResult]:
        """
        Scan binary data for known bug patterns.

        Args:
            data: Binary data to scan
            source_name: Name/path of the data source for reporting
            severity_filter: Only check for bugs of this severity
            category_filter: Only check for bugs of this category

        Returns:
            List of ScanResult objects for detected bugs
        """
        results = []

        # Get bugs with patterns from database
        bugs = self.db.get_all_bugs()

        for bug in bugs:
            # Apply filters
            if severity_filter and bug.severity.value != severity_filter:
                continue
            if category_filter and bug.category.value != category_filter:
                continue

            # Skip bugs without patterns
            if not bug.pattern:
                continue

            # Search for pattern matches
            matches = self._find_pattern_matches(data, bug.pattern)

            for offset, context in matches:
                result = ScanResult(
                    bug=bug,
                    match_location=f"{source_name}:0x{offset:08x}",
                    match_context=context,
                    confidence=self._calculate_confidence(bug, context),
                )
                results.append(result)

        # Sort by confidence (highest first)
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def _find_pattern_matches(
        self,
        data: bytes,
        pattern: str,
    ) -> List[Tuple[int, str]]:
        """
        Find all matches of a pattern in binary data.

        Pattern format:
        - Hex string: "deadbeef" matches those bytes
        - Regex: "/pattern/" uses regex matching on hex representation
        - Byte sequence: "\\x00\\x01" matches byte sequence

        Returns:
            List of (offset, context_hex) tuples
        """
        matches = []

        try:
            if pattern.startswith("/") and pattern.endswith("/"):
                # Regex pattern on hex representation
                regex_pattern = pattern[1:-1]
                hex_data = data.hex()
                for match in re.finditer(regex_pattern, hex_data, re.IGNORECASE):
                    offset = match.start() // 2  # Convert hex position to byte offset
                    context = self._get_context(data, offset, 16)
                    matches.append((offset, context))

            elif all(c in "0123456789abcdefABCDEF" for c in pattern):
                # Plain hex pattern
                pattern_bytes = bytes.fromhex(pattern)
                offset = 0
                while True:
                    pos = data.find(pattern_bytes, offset)
                    if pos == -1:
                        break
                    context = self._get_context(data, pos, 16)
                    matches.append((pos, context))
                    offset = pos + 1

            else:
                # Try as escaped byte sequence
                try:
                    pattern_bytes = pattern.encode().decode("unicode_escape").encode("latin-1")
                    offset = 0
                    while True:
                        pos = data.find(pattern_bytes, offset)
                        if pos == -1:
                            break
                        context = self._get_context(data, pos, 16)
                        matches.append((pos, context))
                        offset = pos + 1
                except (UnicodeDecodeError, ValueError):
                    pass

        except (re.error, ValueError) as e:
            # Invalid pattern, skip
            pass

        return matches

    def _get_context(self, data: bytes, offset: int, size: int) -> str:
        """Get hex context around an offset."""
        start = max(0, offset - size)
        end = min(len(data), offset + size)
        context_bytes = data[start:end]
        return context_bytes.hex()

    def _calculate_confidence(self, bug: Bug, context: str) -> float:
        """
        Calculate confidence score for a match.
        Higher scores indicate more reliable matches.
        """
        confidence = 0.5  # Base confidence

        # Longer patterns are more specific
        if bug.pattern:
            pattern_len = len(bug.pattern.replace("/", ""))
            if pattern_len > 16:
                confidence += 0.2
            elif pattern_len > 8:
                confidence += 0.1

        # CVE-assigned bugs are more credible
        if bug.cve_id:
            confidence += 0.1

        # Higher CVSS scores suggest more significant matches
        if bug.cvss_score and bug.cvss_score >= 7.0:
            confidence += 0.1

        return min(1.0, confidence)

    def quick_scan(
        self,
        file_path: Path,
        patterns: List[str],
    ) -> List[Tuple[str, int, str]]:
        """
        Quick scan without database - just check for specific patterns.

        Args:
            file_path: Path to file to scan
            patterns: List of hex patterns to search for

        Returns:
            List of (pattern, offset, context) tuples
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        results = []
        for pattern in patterns:
            for offset, context in self._find_pattern_matches(data, pattern):
                results.append((pattern, offset, context))

        return results


class PatternGenerator:
    """Helper class for generating common vulnerability patterns."""

    # Common vulnerable function signatures (ARM Cortex-M)
    DANGEROUS_FUNCTIONS = {
        # strcpy-like patterns (ARM thumb)
        "strcpy": "f7ff",  # BL instruction prefix
        # memcpy without bounds check
        "memcpy": "f7ff",
        # sprintf patterns
        "sprintf": "f7ff",
    }

    # Stack canary absence indicators
    STACK_CANARY_MISSING = [
        "e92d4800",  # PUSH without stack guard
    ]

    # Hardcoded key patterns
    CRYPTO_WEAKNESSES = [
        "0001020304050607",  # Sequential test key
        "00000000000000000000000000000000",  # Zero key
        "ffffffffffffffffffffffffffffffff",  # All-ones key
    ]

    # Debug/development leftover patterns
    DEBUG_PATTERNS = [
        "44454255",  # "DEBU" in ASCII
        "54455354",  # "TEST" in ASCII
        "544f444f",  # "TODO" in ASCII
    ]

    @classmethod
    def get_all_patterns(cls) -> dict:
        """Get all predefined vulnerability patterns."""
        return {
            "dangerous_functions": cls.DANGEROUS_FUNCTIONS,
            "stack_canary_missing": cls.STACK_CANARY_MISSING,
            "crypto_weaknesses": cls.CRYPTO_WEAKNESSES,
            "debug_patterns": cls.DEBUG_PATTERNS,
        }

    @classmethod
    def get_firmware_patterns(cls) -> List[str]:
        """Get common patterns for firmware analysis."""
        patterns = []
        patterns.extend(cls.STACK_CANARY_MISSING)
        patterns.extend(cls.CRYPTO_WEAKNESSES)
        patterns.extend(cls.DEBUG_PATTERNS)
        return patterns
