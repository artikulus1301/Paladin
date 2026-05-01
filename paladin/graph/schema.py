"""
Paladin Neo4j graph schema definitions.
Defines all node labels, relationship types, constraints, and indexes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List


# ── Node Labels ────────────────────────────────────────────────────────────────

class NodeLabel(str, Enum):
    EMPLOYEE = "Employee"
    DEVICE = "Device"
    FILE = "File"
    EMAIL = "Email"
    MESSAGE = "Message"
    CALL = "Call"
    LOG_EVENT = "LogEvent"
    IP_ADDRESS = "IPAddress"
    INCIDENT = "Incident"
    DEPARTMENT = "Department"
    ROLE = "Role"
    CLEARANCE_LEVEL = "ClearanceLevel"


# ── Relationship Types ─────────────────────────────────────────────────────────

class RelType(str, Enum):
    # Organisational hierarchy
    MANAGES = "MANAGES"
    MEMBER_OF = "MEMBER_OF"
    HAS_CLEARANCE = "HAS_CLEARANCE"
    CONTAINS = "CONTAINS"           # Department → Employee
    BELONGS_TO = "BELONGS_TO"       # Employee → Department

    # Device / access
    USES_DEVICE = "USES_DEVICE"
    LOGGED_INTO = "LOGGED_INTO"
    CONNECTED_FROM = "CONNECTED_FROM"

    # File operations
    ACCESSED_FILE = "ACCESSED_FILE"
    MODIFIED_FILE = "MODIFIED_FILE"
    DOWNLOADED_FILE = "DOWNLOADED_FILE"
    CREATED_FILE = "CREATED_FILE"

    # Communications
    SENT_EMAIL = "SENT_EMAIL"
    RECEIVED_EMAIL = "RECEIVED_EMAIL"
    SENT_MESSAGE = "SENT_MESSAGE"
    RECEIVED_MESSAGE = "RECEIVED_MESSAGE"
    CALLED = "CALLED"
    RECEIVED_CALL = "RECEIVED_CALL"

    # Network
    CONNECTED_TO_IP = "CONNECTED_TO_IP"

    # Incident
    INVOLVED_IN = "INVOLVED_IN"
    TRIGGERED_BY = "TRIGGERED_BY"
    RELATED_EVENT = "RELATED_EVENT"

    # Process
    STARTED_PROCESS = "STARTED_PROCESS"


# ── Clearance Levels ──────────────────────────────────────────────────────────

class ClearanceLevel(int, Enum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4


# ── Schema Initialisation Queries ──────────────────────────────────────────────

INIT_CONSTRAINTS: List[str] = [
    # Uniqueness constraints
    "CREATE CONSTRAINT employee_uid IF NOT EXISTS FOR (e:Employee) REQUIRE e.uid IS UNIQUE",
    "CREATE CONSTRAINT device_hostname IF NOT EXISTS FOR (d:Device) REQUIRE d.hostname IS UNIQUE",
    "CREATE CONSTRAINT file_path IF NOT EXISTS FOR (f:File) REQUIRE f.path IS UNIQUE",
    "CREATE CONSTRAINT email_message_id IF NOT EXISTS FOR (e:Email) REQUIRE e.message_id IS UNIQUE",
    "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE",
    "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE",
    "CREATE CONSTRAINT department_name IF NOT EXISTS FOR (d:Department) REQUIRE d.name IS UNIQUE",
    "CREATE CONSTRAINT role_name IF NOT EXISTS FOR (r:Role) REQUIRE r.name IS UNIQUE",
    "CREATE CONSTRAINT clearance_name IF NOT EXISTS FOR (c:ClearanceLevel) REQUIRE c.level IS UNIQUE",
]

INIT_INDEXES: List[str] = [
    # Timestamp indexes for temporal correlation
    "CREATE INDEX log_timestamp IF NOT EXISTS FOR (l:LogEvent) ON (l.timestamp)",
    "CREATE INDEX email_timestamp IF NOT EXISTS FOR (e:Email) ON (e.timestamp)",
    "CREATE INDEX message_timestamp IF NOT EXISTS FOR (m:Message) ON (m.timestamp)",
    "CREATE INDEX call_timestamp IF NOT EXISTS FOR (c:Call) ON (c.timestamp)",
    "CREATE INDEX incident_created IF NOT EXISTS FOR (i:Incident) ON (i.created_at)",

    # Risk score indexes
    "CREATE INDEX log_risk IF NOT EXISTS FOR (l:LogEvent) ON (l.risk_score)",
    "CREATE INDEX email_risk IF NOT EXISTS FOR (e:Email) ON (e.risk_score)",

    # Employee lookup
    "CREATE INDEX employee_name IF NOT EXISTS FOR (e:Employee) ON (e.full_name)",
    "CREATE INDEX employee_department IF NOT EXISTS FOR (e:Employee) ON (e.department)",

    # File classification
    "CREATE INDEX file_clearance IF NOT EXISTS FOR (f:File) ON (f.clearance_level)",

    # Archive flag
    "CREATE INDEX log_archived IF NOT EXISTS FOR (l:LogEvent) ON (l.archived)",
]


# ── Seed Data: Departments, Roles, Clearance ──────────────────────────────────

SEED_DEPARTMENTS = [
    "Engineering", "Finance", "HR", "Legal",
    "Operations", "Sales", "IT Security", "Executive",
]

SEED_ROLES = [
    {"name": "Junior Developer", "clearance": ClearanceLevel.INTERNAL},
    {"name": "Senior Developer", "clearance": ClearanceLevel.CONFIDENTIAL},
    {"name": "Team Lead", "clearance": ClearanceLevel.CONFIDENTIAL},
    {"name": "Manager", "clearance": ClearanceLevel.SECRET},
    {"name": "Director", "clearance": ClearanceLevel.SECRET},
    {"name": "VP", "clearance": ClearanceLevel.TOP_SECRET},
    {"name": "CTO", "clearance": ClearanceLevel.TOP_SECRET},
    {"name": "CEO", "clearance": ClearanceLevel.TOP_SECRET},
    {"name": "Accountant", "clearance": ClearanceLevel.CONFIDENTIAL},
    {"name": "HR Specialist", "clearance": ClearanceLevel.CONFIDENTIAL},
    {"name": "Security Analyst", "clearance": ClearanceLevel.SECRET},
    {"name": "Intern", "clearance": ClearanceLevel.PUBLIC},
    {"name": "Contractor", "clearance": ClearanceLevel.INTERNAL},
    {"name": "System Administrator", "clearance": ClearanceLevel.SECRET},
]

SEED_CLEARANCE_LEVELS = [
    {"level": ClearanceLevel.PUBLIC, "name": "Public", "description": "Publicly available data"},
    {"level": ClearanceLevel.INTERNAL, "name": "Internal", "description": "Internal company data"},
    {"level": ClearanceLevel.CONFIDENTIAL, "name": "Confidential", "description": "Business-sensitive data"},
    {"level": ClearanceLevel.SECRET, "name": "Secret", "description": "Strategic and financial data"},
    {"level": ClearanceLevel.TOP_SECRET, "name": "Top Secret", "description": "Board-level and M&A data"},
]
