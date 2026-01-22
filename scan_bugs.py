#!/usr/bin/env python3
"""
Bug Database Scanner - Convenience entry point.
Searches for bugs/vulnerabilities in firmware dumps and binary files.

Usage:
    ./scan_bugs.py init                    # Initialize with sample bug patterns
    ./scan_bugs.py add "Bug Name" ...      # Add a new bug
    ./scan_bugs.py list                    # List all bugs
    ./scan_bugs.py scan firmware.bin       # Scan a file for bugs
    ./scan_bugs.py --help                  # Show all commands
"""

import sys
from pathlib import Path

# Add package to path for direct execution
sys.path.insert(0, str(Path(__file__).parent))

from bug_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
