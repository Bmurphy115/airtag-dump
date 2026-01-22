"""
Entry point for running bug_scanner as a module.
Usage: python -m bug_scanner [command] [options]
"""

from .cli import main

if __name__ == "__main__":
    exit(main())
