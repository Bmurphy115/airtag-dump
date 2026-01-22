"""
Command-line interface for the bug scanner.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .database import BugDatabase
from .models import Bug, BugCategory, BugStatus, Severity
from .scanner import BugScanner, PatternGenerator


def format_bug(bug: Bug, verbose: bool = False) -> str:
    """Format a bug for display."""
    severity_colors = {
        "critical": "\033[91m",  # Red
        "high": "\033[93m",      # Yellow
        "medium": "\033[94m",    # Blue
        "low": "\033[92m",       # Green
        "info": "\033[90m",      # Gray
    }
    reset = "\033[0m"

    color = severity_colors.get(bug.severity.value, "")
    severity_str = f"{color}[{bug.severity.value.upper()}]{reset}"

    output = f"{severity_str} #{bug.id}: {bug.name}\n"
    output += f"  Category: {bug.category.value} | Status: {bug.status.value}\n"
    output += f"  Component: {bug.affected_component}\n"

    if verbose:
        output += f"  Description: {bug.description}\n"
        if bug.cve_id:
            output += f"  CVE: {bug.cve_id}\n"
        if bug.cvss_score:
            output += f"  CVSS: {bug.cvss_score}\n"
        if bug.memory_address:
            output += f"  Address: {bug.memory_address}\n"
        if bug.pattern:
            output += f"  Pattern: {bug.pattern}\n"
        if bug.notes:
            output += f"  Notes: {bug.notes}\n"
        output += f"  Discovered: {bug.discovery_date.strftime('%Y-%m-%d')}\n"

    return output


def cmd_add(args, db: BugDatabase) -> int:
    """Add a new bug to the database."""
    now = datetime.now()

    try:
        severity = Severity(args.severity)
    except ValueError:
        print(f"Invalid severity: {args.severity}")
        print(f"Valid options: {', '.join(s.value for s in Severity)}")
        return 1

    try:
        category = BugCategory(args.category)
    except ValueError:
        print(f"Invalid category: {args.category}")
        print(f"Valid options: {', '.join(c.value for c in BugCategory)}")
        return 1

    bug = Bug(
        id=None,
        name=args.name,
        description=args.description,
        severity=severity,
        category=category,
        status=BugStatus.OPEN,
        affected_component=args.component,
        pattern=args.pattern,
        cve_id=args.cve,
        cvss_score=args.cvss,
        memory_address=args.address,
        firmware_version=args.firmware,
        discovery_date=now,
        last_updated=now,
        notes=args.notes,
    )

    bug_id = db.insert_bug(bug)
    print(f"Bug #{bug_id} added successfully.")
    return 0


def cmd_list(args, db: BugDatabase) -> int:
    """List bugs from the database."""
    severity = Severity(args.severity) if args.severity else None
    category = BugCategory(args.category) if args.category else None
    status = BugStatus(args.status) if args.status else None

    bugs = db.search_bugs(
        query=args.query,
        severity=severity,
        category=category,
        status=status,
        component=args.component,
        cve_id=args.cve,
    )

    if not bugs:
        print("No bugs found matching the criteria.")
        return 0

    if args.json:
        output = [bug.to_dict() for bug in bugs]
        print(json.dumps(output, indent=2))
    else:
        for bug in bugs:
            print(format_bug(bug, verbose=args.verbose))

    print(f"\nTotal: {len(bugs)} bug(s)")
    return 0


def cmd_show(args, db: BugDatabase) -> int:
    """Show details of a specific bug."""
    bug = db.get_bug(args.id)
    if not bug:
        print(f"Bug #{args.id} not found.")
        return 1

    if args.json:
        print(json.dumps(bug.to_dict(), indent=2))
    else:
        print(format_bug(bug, verbose=True))
    return 0


def cmd_update(args, db: BugDatabase) -> int:
    """Update an existing bug."""
    bug = db.get_bug(args.id)
    if not bug:
        print(f"Bug #{args.id} not found.")
        return 1

    if args.status:
        try:
            bug.status = BugStatus(args.status)
        except ValueError:
            print(f"Invalid status: {args.status}")
            return 1

    if args.severity:
        try:
            bug.severity = Severity(args.severity)
        except ValueError:
            print(f"Invalid severity: {args.severity}")
            return 1

    if args.notes:
        bug.notes = args.notes

    if args.cve:
        bug.cve_id = args.cve

    if args.cvss is not None:
        bug.cvss_score = args.cvss

    if db.update_bug(bug):
        print(f"Bug #{args.id} updated successfully.")
        return 0
    else:
        print(f"Failed to update bug #{args.id}.")
        return 1


def cmd_delete(args, db: BugDatabase) -> int:
    """Delete a bug from the database."""
    if not args.force:
        confirm = input(f"Delete bug #{args.id}? [y/N]: ")
        if confirm.lower() != "y":
            print("Cancelled.")
            return 0

    if db.delete_bug(args.id):
        print(f"Bug #{args.id} deleted.")
        return 0
    else:
        print(f"Bug #{args.id} not found.")
        return 1


def cmd_scan(args, db: BugDatabase) -> int:
    """Scan a file for known bug patterns."""
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"File not found: {file_path}")
        return 1

    scanner = BugScanner(db)

    print(f"Scanning {file_path}...")
    results = scanner.scan_file(
        file_path,
        severity_filter=args.severity,
        category_filter=args.category,
    )

    if not results:
        print("No matches found.")

        if args.quick:
            print("\nRunning quick scan with common patterns...")
            patterns = PatternGenerator.get_firmware_patterns()
            quick_results = scanner.quick_scan(file_path, patterns)
            if quick_results:
                print(f"\nFound {len(quick_results)} pattern match(es):")
                for pattern, offset, context in quick_results:
                    print(f"  Pattern: {pattern}")
                    print(f"  Offset:  0x{offset:08x}")
                    print(f"  Context: {context}")
                    print()
            else:
                print("No common patterns found.")
        return 0

    print(f"\nFound {len(results)} potential match(es):\n")

    if args.json:
        output = [r.to_dict() for r in results]
        print(json.dumps(output, indent=2))
    else:
        for result in results:
            print(f"Match: {result.bug.name}")
            print(f"  Location:   {result.match_location}")
            print(f"  Confidence: {result.confidence:.0%}")
            print(f"  Severity:   {result.bug.severity.value}")
            print(f"  Category:   {result.bug.category.value}")
            if result.match_context:
                print(f"  Context:    {result.match_context}")
            print()

    return 0


def cmd_stats(args, db: BugDatabase) -> int:
    """Show database statistics."""
    stats = db.get_statistics()

    if args.json:
        print(json.dumps(stats, indent=2))
        return 0

    print("Bug Database Statistics")
    print("=" * 40)
    print(f"Total bugs: {stats['total_bugs']}")
    print()

    if stats["by_severity"]:
        print("By Severity:")
        for sev, count in sorted(stats["by_severity"].items()):
            print(f"  {sev}: {count}")
        print()

    if stats["by_category"]:
        print("By Category:")
        for cat, count in sorted(stats["by_category"].items()):
            print(f"  {cat}: {count}")
        print()

    if stats["by_status"]:
        print("By Status:")
        for status, count in sorted(stats["by_status"].items()):
            print(f"  {status}: {count}")
        print()

    if stats["avg_cvss"]:
        print(f"Average CVSS: {stats['avg_cvss']}")

    return 0


def cmd_import(args, db: BugDatabase) -> int:
    """Import bugs from a JSON file."""
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"File not found: {file_path}")
        return 1

    try:
        with open(file_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        return 1

    if not isinstance(data, list):
        data = [data]

    count = 0
    for item in data:
        try:
            bug = Bug.from_dict(item)
            bug.id = None  # Force new ID on import
            db.insert_bug(bug)
            count += 1
        except (KeyError, ValueError) as e:
            print(f"Skipping invalid entry: {e}")

    print(f"Imported {count} bug(s).")
    return 0


def cmd_export(args, db: BugDatabase) -> int:
    """Export bugs to a JSON file."""
    bugs = db.get_all_bugs()
    output = [bug.to_dict() for bug in bugs]

    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"Exported {len(bugs)} bug(s) to {args.output}")
    else:
        print(json.dumps(output, indent=2))

    return 0


def cmd_init(args, db: BugDatabase) -> int:
    """Initialize database with sample firmware bug patterns."""
    from .sample_bugs import get_sample_bugs

    sample_bugs = get_sample_bugs()
    count = 0

    for bug in sample_bugs:
        db.insert_bug(bug)
        count += 1

    print(f"Initialized database with {count} sample bug pattern(s).")
    return 0


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="bug_scanner",
        description="Bug Database Scanner - Search and catalog security vulnerabilities",
    )
    parser.add_argument(
        "--db",
        type=Path,
        help="Path to database file (default: bugs.db)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new bug")
    add_parser.add_argument("name", help="Bug name/title")
    add_parser.add_argument("description", help="Bug description")
    add_parser.add_argument("-s", "--severity", required=True,
                          choices=[s.value for s in Severity],
                          help="Bug severity")
    add_parser.add_argument("-c", "--category", required=True,
                          choices=[c.value for c in BugCategory],
                          help="Bug category")
    add_parser.add_argument("--component", required=True,
                          help="Affected component")
    add_parser.add_argument("-p", "--pattern", help="Detection pattern (hex/regex)")
    add_parser.add_argument("--cve", help="CVE identifier")
    add_parser.add_argument("--cvss", type=float, help="CVSS score (0-10)")
    add_parser.add_argument("-a", "--address", help="Memory address (hex)")
    add_parser.add_argument("--firmware", help="Firmware version")
    add_parser.add_argument("-n", "--notes", help="Additional notes")

    # List command
    list_parser = subparsers.add_parser("list", help="List/search bugs")
    list_parser.add_argument("-q", "--query", help="Text search")
    list_parser.add_argument("-s", "--severity",
                           choices=[s.value for s in Severity],
                           help="Filter by severity")
    list_parser.add_argument("-c", "--category",
                           choices=[c.value for c in BugCategory],
                           help="Filter by category")
    list_parser.add_argument("--status",
                           choices=[s.value for s in BugStatus],
                           help="Filter by status")
    list_parser.add_argument("--component", help="Filter by component")
    list_parser.add_argument("--cve", help="Filter by CVE")
    list_parser.add_argument("-v", "--verbose", action="store_true",
                           help="Show full details")
    list_parser.add_argument("--json", action="store_true",
                           help="Output as JSON")

    # Show command
    show_parser = subparsers.add_parser("show", help="Show bug details")
    show_parser.add_argument("id", type=int, help="Bug ID")
    show_parser.add_argument("--json", action="store_true",
                           help="Output as JSON")

    # Update command
    update_parser = subparsers.add_parser("update", help="Update a bug")
    update_parser.add_argument("id", type=int, help="Bug ID")
    update_parser.add_argument("--status",
                             choices=[s.value for s in BugStatus],
                             help="New status")
    update_parser.add_argument("-s", "--severity",
                             choices=[s.value for s in Severity],
                             help="New severity")
    update_parser.add_argument("--cve", help="CVE identifier")
    update_parser.add_argument("--cvss", type=float, help="CVSS score")
    update_parser.add_argument("-n", "--notes", help="Notes")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a bug")
    delete_parser.add_argument("id", type=int, help="Bug ID")
    delete_parser.add_argument("-f", "--force", action="store_true",
                             help="Skip confirmation")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan file for bugs")
    scan_parser.add_argument("file", help="File to scan")
    scan_parser.add_argument("-s", "--severity",
                           choices=[s.value for s in Severity],
                           help="Filter patterns by severity")
    scan_parser.add_argument("-c", "--category",
                           choices=[c.value for c in BugCategory],
                           help="Filter patterns by category")
    scan_parser.add_argument("--quick", action="store_true",
                           help="Also run quick scan with common patterns")
    scan_parser.add_argument("--json", action="store_true",
                           help="Output as JSON")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show statistics")
    stats_parser.add_argument("--json", action="store_true",
                            help="Output as JSON")

    # Import command
    import_parser = subparsers.add_parser("import", help="Import bugs from JSON")
    import_parser.add_argument("file", help="JSON file to import")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export bugs to JSON")
    export_parser.add_argument("-o", "--output", help="Output file")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize with sample bugs")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Command handlers
    handlers = {
        "add": cmd_add,
        "list": cmd_list,
        "show": cmd_show,
        "update": cmd_update,
        "delete": cmd_delete,
        "scan": cmd_scan,
        "stats": cmd_stats,
        "import": cmd_import,
        "export": cmd_export,
        "init": cmd_init,
    }

    with BugDatabase(args.db) as db:
        return handlers[args.command](args, db)


if __name__ == "__main__":
    sys.exit(main())
