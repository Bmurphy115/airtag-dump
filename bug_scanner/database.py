"""
Database operations for the bug scanner.
Uses SQLite for portable, file-based storage.
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import Bug, BugCategory, BugStatus, Severity


class BugDatabase:
    """SQLite database manager for bug tracking."""

    DEFAULT_DB_PATH = Path(__file__).parent.parent / "bugs.db"

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize database connection."""
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self.connection: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        """Establish database connection."""
        self.connection = sqlite3.connect(str(self.db_path))
        self.connection.row_factory = sqlite3.Row
        self._create_tables()

    def close(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None

    def __enter__(self) -> "BugDatabase":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _create_tables(self) -> None:
        """Create database tables if they don't exist."""
        cursor = self.connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bugs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                affected_component TEXT NOT NULL,
                pattern TEXT,
                cve_id TEXT,
                cvss_score REAL,
                memory_address TEXT,
                firmware_version TEXT,
                discovery_date TEXT NOT NULL,
                last_updated TEXT NOT NULL,
                notes TEXT
            )
        """)

        # Create indexes for common search fields
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bugs_severity ON bugs(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bugs_category ON bugs(category)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bugs_status ON bugs(status)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bugs_component ON bugs(affected_component)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bugs_cve ON bugs(cve_id)
        """)

        self.connection.commit()

    def insert_bug(self, bug: Bug) -> int:
        """Insert a new bug into the database. Returns the new bug ID."""
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO bugs (
                name, description, severity, category, status,
                affected_component, pattern, cve_id, cvss_score,
                memory_address, firmware_version, discovery_date,
                last_updated, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            bug.name,
            bug.description,
            bug.severity.value,
            bug.category.value,
            bug.status.value,
            bug.affected_component,
            bug.pattern,
            bug.cve_id,
            bug.cvss_score,
            bug.memory_address,
            bug.firmware_version,
            bug.discovery_date.isoformat(),
            bug.last_updated.isoformat(),
            bug.notes,
        ))
        self.connection.commit()
        return cursor.lastrowid

    def update_bug(self, bug: Bug) -> bool:
        """Update an existing bug. Returns True if successful."""
        if bug.id is None:
            return False

        cursor = self.connection.cursor()
        cursor.execute("""
            UPDATE bugs SET
                name = ?, description = ?, severity = ?, category = ?,
                status = ?, affected_component = ?, pattern = ?,
                cve_id = ?, cvss_score = ?, memory_address = ?,
                firmware_version = ?, last_updated = ?, notes = ?
            WHERE id = ?
        """, (
            bug.name,
            bug.description,
            bug.severity.value,
            bug.category.value,
            bug.status.value,
            bug.affected_component,
            bug.pattern,
            bug.cve_id,
            bug.cvss_score,
            bug.memory_address,
            bug.firmware_version,
            datetime.now().isoformat(),
            bug.notes,
            bug.id,
        ))
        self.connection.commit()
        return cursor.rowcount > 0

    def delete_bug(self, bug_id: int) -> bool:
        """Delete a bug by ID. Returns True if successful."""
        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM bugs WHERE id = ?", (bug_id,))
        self.connection.commit()
        return cursor.rowcount > 0

    def get_bug(self, bug_id: int) -> Optional[Bug]:
        """Get a bug by ID."""
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM bugs WHERE id = ?", (bug_id,))
        row = cursor.fetchone()
        return self._row_to_bug(row) if row else None

    def get_all_bugs(self) -> List[Bug]:
        """Get all bugs from the database."""
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM bugs ORDER BY discovery_date DESC")
        return [self._row_to_bug(row) for row in cursor.fetchall()]

    def search_bugs(
        self,
        query: Optional[str] = None,
        severity: Optional[Severity] = None,
        category: Optional[BugCategory] = None,
        status: Optional[BugStatus] = None,
        component: Optional[str] = None,
        cve_id: Optional[str] = None,
        min_cvss: Optional[float] = None,
        max_cvss: Optional[float] = None,
    ) -> List[Bug]:
        """
        Search bugs with various filters.

        Args:
            query: Text search in name, description, and notes
            severity: Filter by severity level
            category: Filter by bug category
            status: Filter by bug status
            component: Filter by affected component (partial match)
            cve_id: Filter by CVE ID (partial match)
            min_cvss: Minimum CVSS score
            max_cvss: Maximum CVSS score

        Returns:
            List of matching Bug objects
        """
        conditions = []
        params = []

        if query:
            conditions.append(
                "(name LIKE ? OR description LIKE ? OR notes LIKE ?)"
            )
            search_pattern = f"%{query}%"
            params.extend([search_pattern, search_pattern, search_pattern])

        if severity:
            conditions.append("severity = ?")
            params.append(severity.value)

        if category:
            conditions.append("category = ?")
            params.append(category.value)

        if status:
            conditions.append("status = ?")
            params.append(status.value)

        if component:
            conditions.append("affected_component LIKE ?")
            params.append(f"%{component}%")

        if cve_id:
            conditions.append("cve_id LIKE ?")
            params.append(f"%{cve_id}%")

        if min_cvss is not None:
            conditions.append("cvss_score >= ?")
            params.append(min_cvss)

        if max_cvss is not None:
            conditions.append("cvss_score <= ?")
            params.append(max_cvss)

        sql = "SELECT * FROM bugs"
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY cvss_score DESC NULLS LAST, severity ASC"

        cursor = self.connection.cursor()
        cursor.execute(sql, params)
        return [self._row_to_bug(row) for row in cursor.fetchall()]

    def get_statistics(self) -> dict:
        """Get statistics about the bug database."""
        cursor = self.connection.cursor()

        stats = {
            "total_bugs": 0,
            "by_severity": {},
            "by_category": {},
            "by_status": {},
            "avg_cvss": None,
        }

        # Total count
        cursor.execute("SELECT COUNT(*) FROM bugs")
        stats["total_bugs"] = cursor.fetchone()[0]

        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM bugs GROUP BY severity
        """)
        stats["by_severity"] = {row["severity"]: row["count"] for row in cursor.fetchall()}

        # By category
        cursor.execute("""
            SELECT category, COUNT(*) as count
            FROM bugs GROUP BY category
        """)
        stats["by_category"] = {row["category"]: row["count"] for row in cursor.fetchall()}

        # By status
        cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM bugs GROUP BY status
        """)
        stats["by_status"] = {row["status"]: row["count"] for row in cursor.fetchall()}

        # Average CVSS
        cursor.execute("SELECT AVG(cvss_score) FROM bugs WHERE cvss_score IS NOT NULL")
        result = cursor.fetchone()[0]
        stats["avg_cvss"] = round(result, 2) if result else None

        return stats

    def _row_to_bug(self, row: sqlite3.Row) -> Bug:
        """Convert a database row to a Bug object."""
        return Bug(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            severity=Severity(row["severity"]),
            category=BugCategory(row["category"]),
            status=BugStatus(row["status"]),
            affected_component=row["affected_component"],
            pattern=row["pattern"],
            cve_id=row["cve_id"],
            cvss_score=row["cvss_score"],
            memory_address=row["memory_address"],
            firmware_version=row["firmware_version"],
            discovery_date=datetime.fromisoformat(row["discovery_date"]),
            last_updated=datetime.fromisoformat(row["last_updated"]),
            notes=row["notes"],
        )
