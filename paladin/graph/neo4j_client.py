"""
Paladin Neo4j client — extended from Richter.
Manages connection, schema initialization, seed data,
and all CRUD operations for the security graph.
"""
from __future__ import annotations

import asyncio
from typing import Optional, Any

import structlog
from neo4j import AsyncGraphDatabase, AsyncDriver
from tenacity import retry, stop_after_attempt, wait_exponential

from paladin.config.settings import settings
from paladin.graph.schema import (
    INIT_CONSTRAINTS, INIT_INDEXES,
    SEED_DEPARTMENTS, SEED_ROLES, SEED_CLEARANCE_LEVELS,
    NodeLabel, RelType, ClearanceLevel,
)

log = structlog.get_logger(__name__)


class Neo4jClient:
    """Async Neo4j driver wrapper for the Paladin security graph."""

    def __init__(self) -> None:
        self._driver: Optional[AsyncDriver] = None

    async def connect(self) -> None:
        self._driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_pool_size=30,
        )
        await self._driver.verify_connectivity()
        await self._init_schema()
        log.info("neo4j_connected", uri=settings.neo4j_uri)

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()

    # ── Schema bootstrap ──────────────────────────────────────────────────────
    async def _init_schema(self) -> None:
        async with self._driver.session() as session:
            for cql in INIT_CONSTRAINTS + INIT_INDEXES:
                try:
                    await session.run(cql)
                except Exception as e:
                    log.debug("schema_item_exists", query=cql[:60], error=str(e))

    async def seed_organization(self) -> None:
        """Create departments, roles, and clearance level nodes."""
        async with self._driver.session() as session:
            # Clearance levels
            for cl in SEED_CLEARANCE_LEVELS:
                await session.run(
                    """
                    MERGE (c:ClearanceLevel {level: $level})
                    ON CREATE SET c.name = $name, c.description = $desc
                    """,
                    level=cl["level"].value, name=cl["name"], desc=cl["description"],
                )
            # Departments
            for dept in SEED_DEPARTMENTS:
                await session.run(
                    "MERGE (d:Department {name: $name})",
                    name=dept,
                )
            # Roles + clearance links
            for role in SEED_ROLES:
                await session.run(
                    """
                    MERGE (r:Role {name: $name})
                    WITH r
                    MATCH (c:ClearanceLevel {level: $cl})
                    MERGE (r)-[:HAS_CLEARANCE]->(c)
                    """,
                    name=role["name"], cl=role["clearance"].value,
                )
        log.info("organization_seeded")

    # ── Employee CRUD ─────────────────────────────────────────────────────────
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def upsert_employee(self, employee: dict) -> None:
        """
        employee dict keys: uid, full_name, email, department, role, manager_uid (optional)
        """
        async with self._driver.session() as session:
            await session.run(
                """
                MERGE (e:Employee {uid: $uid})
                SET e.full_name   = $full_name,
                    e.email       = $email,
                    e.department  = $department,
                    e.role_name   = $role,
                    e.updated_at  = datetime()
                WITH e
                MATCH (d:Department {name: $department})
                MERGE (d)-[:CONTAINS]->(e)
                MERGE (e)-[:BELONGS_TO]->(d)
                WITH e
                MATCH (r:Role {name: $role})
                MERGE (e)-[:MEMBER_OF]->(r)
                """,
                **employee,
            )
            # Manager link
            if employee.get("manager_uid"):
                await session.run(
                    """
                    MATCH (mgr:Employee {uid: $mgr_uid}), (emp:Employee {uid: $uid})
                    MERGE (mgr)-[:MANAGES]->(emp)
                    """,
                    mgr_uid=employee["manager_uid"], uid=employee["uid"],
                )

    # ── Event ingestion ───────────────────────────────────────────────────────
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def write_log_event(self, event: dict) -> str:
        """Write a LogEvent node and connect to Employee/Device/IP."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                CREATE (l:LogEvent {
                    event_id:   $event_id,
                    event_type: $event_type,
                    timestamp:  datetime($timestamp),
                    source:     $source,
                    details:    $details,
                    risk_score: $risk_score,
                    raw_path:   $raw_path,
                    archived:   false
                })
                WITH l
                MATCH (e:Employee {uid: $employee_uid})
                MERGE (e)-[:LOGGED_INTO {timestamp: datetime($timestamp)}]->(l)
                RETURN elementId(l) AS node_id
                """,
                **event,
            )
            record = await result.single()
            node_id = record["node_id"] if record else "unknown"

            # Device link
            if event.get("device_hostname"):
                await session.run(
                    """
                    MERGE (d:Device {hostname: $hostname})
                    WITH d
                    MATCH (l:LogEvent {event_id: $event_id})
                    MERGE (l)-[:OCCURRED_ON]->(d)
                    """,
                    hostname=event["device_hostname"], event_id=event["event_id"],
                )

            # IP link
            if event.get("ip_address"):
                await session.run(
                    """
                    MERGE (ip:IPAddress {address: $address})
                    WITH ip
                    MATCH (l:LogEvent {event_id: $event_id})
                    MERGE (l)-[:CONNECTED_FROM]->(ip)
                    """,
                    address=event["ip_address"], event_id=event["event_id"],
                )

            return node_id

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def write_email(self, email: dict) -> str:
        """Write an Email node and link sender/recipients."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                CREATE (em:Email {
                    message_id:  $message_id,
                    subject:     $subject,
                    timestamp:   datetime($timestamp),
                    risk_score:  $risk_score,
                    has_attachment: $has_attachment,
                    raw_path:    $raw_path,
                    entities:    $entities,
                    sentiment:   $sentiment,
                    archived:    false
                })
                WITH em
                MATCH (sender:Employee {uid: $sender_uid})
                MERGE (sender)-[:SENT_EMAIL {timestamp: datetime($timestamp)}]->(em)
                RETURN elementId(em) AS node_id
                """,
                **email,
            )
            record = await result.single()
            node_id = record["node_id"] if record else "unknown"

            # Recipients
            for rcpt_uid in email.get("recipient_uids", []):
                await session.run(
                    """
                    MATCH (em:Email {message_id: $mid}), (r:Employee {uid: $ruid})
                    MERGE (r)-[:RECEIVED_EMAIL {timestamp: datetime($ts)}]->(em)
                    """,
                    mid=email["message_id"], ruid=rcpt_uid, ts=email["timestamp"],
                )
            return node_id

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def write_message(self, msg: dict) -> str:
        """Write a Message node (corporate messenger)."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                CREATE (m:Message {
                    msg_id:      $msg_id,
                    channel:     $channel,
                    timestamp:   datetime($timestamp),
                    risk_score:  $risk_score,
                    raw_path:    $raw_path,
                    entities:    $entities,
                    sentiment:   $sentiment,
                    archived:    false
                })
                WITH m
                MATCH (sender:Employee {uid: $sender_uid})
                MERGE (sender)-[:SENT_MESSAGE {timestamp: datetime($timestamp)}]->(m)
                RETURN elementId(m) AS node_id
                """,
                **msg,
            )
            record = await result.single()
            node_id = record["node_id"] if record else "unknown"

            for rcpt_uid in msg.get("recipient_uids", []):
                await session.run(
                    """
                    MATCH (m:Message {msg_id: $mid}), (r:Employee {uid: $ruid})
                    MERGE (r)-[:RECEIVED_MESSAGE {timestamp: datetime($ts)}]->(m)
                    """,
                    mid=msg["msg_id"], ruid=rcpt_uid, ts=msg["timestamp"],
                )
            return node_id

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def write_call(self, call: dict) -> str:
        """Write a Call node (voice transcript)."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                CREATE (c:Call {
                    call_id:     $call_id,
                    timestamp:   datetime($timestamp),
                    duration_s:  $duration_s,
                    risk_score:  $risk_score,
                    raw_path:    $raw_path,
                    entities:    $entities,
                    sentiment:   $sentiment,
                    archived:    false
                })
                WITH c
                MATCH (caller:Employee {uid: $caller_uid})
                MERGE (caller)-[:CALLED {timestamp: datetime($timestamp)}]->(c)
                WITH c
                MATCH (callee:Employee {uid: $callee_uid})
                MERGE (callee)-[:RECEIVED_CALL {timestamp: datetime($timestamp)}]->(c)
                RETURN elementId(c) AS node_id
                """,
                **call,
            )
            record = await result.single()
            return record["node_id"] if record else "unknown"

    # ── File access tracking ──────────────────────────────────────────────────
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def write_file_access(self, access: dict) -> None:
        """Track file access: employee accessed/modified/downloaded a file."""
        rel_type = access.get("operation", "ACCESSED_FILE").upper()
        if rel_type not in ("ACCESSED_FILE", "MODIFIED_FILE", "DOWNLOADED_FILE", "CREATED_FILE"):
            rel_type = "ACCESSED_FILE"

        async with self._driver.session() as session:
            await session.run(
                f"""
                MERGE (f:File {{path: $path}})
                ON CREATE SET f.clearance_level = $clearance_level,
                              f.created_at = datetime()
                WITH f
                MATCH (e:Employee {{uid: $employee_uid}})
                MERGE (e)-[:{rel_type} {{timestamp: datetime($timestamp)}}]->(f)
                """,
                path=access["path"],
                clearance_level=access.get("clearance_level", 0),
                employee_uid=access["employee_uid"],
                timestamp=access["timestamp"],
            )

    # ── Incident management ───────────────────────────────────────────────────
    async def create_incident(self, incident: dict) -> str:
        """Create an Incident node linked to involved entities."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                CREATE (i:Incident {
                    incident_id: $incident_id,
                    title:       $title,
                    description: $description,
                    severity:    $severity,
                    score:       $score,
                    status:      "open",
                    created_at:  datetime(),
                    updated_at:  datetime(),
                    llm_summary: "",
                    action_proposed: "",
                    action_status:   "investigating",
                    operator_note:   ""
                })
                RETURN elementId(i) AS node_id
                """,
                **incident,
            )
            record = await result.single()
            node_id = record["node_id"] if record else "unknown"

            # Link involved employees
            for emp_uid in incident.get("involved_employees", []):
                await session.run(
                    """
                    MATCH (i:Incident {incident_id: $iid}), (e:Employee {uid: $uid})
                    MERGE (e)-[:INVOLVED_IN]->(i)
                    """,
                    iid=incident["incident_id"], uid=emp_uid,
                )

            # Link triggering events
            for event_id in incident.get("trigger_event_ids", []):
                await session.run(
                    """
                    MATCH (i:Incident {incident_id: $iid})
                    OPTIONAL MATCH (l:LogEvent {event_id: $eid})
                    OPTIONAL MATCH (em:Email {message_id: $eid})
                    OPTIONAL MATCH (m:Message {msg_id: $eid})
                    OPTIONAL MATCH (c:Call {call_id: $eid})
                    WITH i, coalesce(l, em, m, c) AS event
                    WHERE event IS NOT NULL
                    MERGE (event)-[:TRIGGERED_BY]->(i)
                    """,
                    iid=incident["incident_id"], eid=event_id,
                )
            return node_id

    async def update_incident(self, incident_id: str, updates: dict) -> None:
        """Update incident fields (status, llm_summary, action, operator_note)."""
        set_clauses = ", ".join(f"i.{k} = ${k}" for k in updates)
        updates["iid"] = incident_id
        async with self._driver.session() as session:
            await session.run(
                f"""
                MATCH (i:Incident {{incident_id: $iid}})
                SET {set_clauses}, i.updated_at = datetime()
                """,
                **updates,
            )

    async def find_similar_open_incident(self, title: str, employee_uids: list[str]) -> str | None:
        """Find an existing open incident with the same title for the same employees."""
        if not employee_uids:
            return None
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (i:Incident)
                WHERE i.status IN ["open", "investigating"]
                  AND i.title = $title
                MATCH (e:Employee)-[:INVOLVED_IN]->(i)
                WHERE e.uid IN $uids
                RETURN i.incident_id AS incident_id
                ORDER BY i.created_at DESC
                LIMIT 1
                """,
                title=title, uids=employee_uids,
            )
            record = await result.single()
            return record["incident_id"] if record else None

    async def add_events_to_incident(self, incident_id: str, event_ids: list[str], score: float, severity: str) -> None:
        """Append new triggering events and update severity/score to an existing incident."""
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (i:Incident {incident_id: $iid})
                // Update score and severity if higher
                SET i.score = case when $score > i.score then $score else i.score end,
                    i.severity = case 
                        when $severity = 'CRITICAL' then 'CRITICAL'
                        when $severity = 'HIGH' and i.severity IN ['MEDIUM', 'LOW'] then 'HIGH'
                        when $severity = 'MEDIUM' and i.severity = 'LOW' then 'MEDIUM'
                        else i.severity 
                    end,
                    i.updated_at = datetime()
                WITH i
                UNWIND $event_ids AS eid
                OPTIONAL MATCH (l:LogEvent {event_id: eid})
                OPTIONAL MATCH (em:Email {message_id: eid})
                OPTIONAL MATCH (m:Message {msg_id: eid})
                OPTIONAL MATCH (c:Call {call_id: eid})
                WITH i, coalesce(l, em, m, c) AS event
                WHERE event IS NOT NULL
                MERGE (event)-[:TRIGGERED_BY]->(i)
                """,
                iid=incident_id, event_ids=event_ids, score=score, severity=severity
            )

    # ── Correlation queries ───────────────────────────────────────────────────
    async def get_recent_events_for_employee(
        self, employee_uid: str, minutes: int = 60
    ) -> list[dict]:
        """Get all events linked to an employee in the last N minutes."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (e:Employee {uid: $uid})-[r]->(event)
                WHERE event.timestamp > datetime() - duration({minutes: $minutes})
                  AND (event:LogEvent OR event:Email OR event:Message OR event:Call)
                RETURN labels(event)[0] AS event_type,
                       event.risk_score AS risk_score,
                       event.timestamp AS timestamp,
                       type(r) AS relation,
                       properties(event) AS props
                ORDER BY event.timestamp DESC
                """,
                uid=employee_uid, minutes=minutes,
            )
            return await result.data()

    async def check_clearance_violation(
        self, employee_uid: str, file_path: str
    ) -> Optional[dict]:
        """Check if employee's clearance level is below file's clearance level."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (e:Employee {uid: $uid})-[:MEMBER_OF]->(r:Role)-[:HAS_CLEARANCE]->(ec:ClearanceLevel)
                MATCH (f:File {path: $path})
                WHERE f.clearance_level > ec.level
                RETURN e.full_name AS employee, r.name AS role,
                       ec.level AS emp_clearance, f.clearance_level AS file_clearance,
                       f.path AS file_path
                """,
                uid=employee_uid, path=file_path,
            )
            record = await result.single()
            return dict(record) if record else None

    async def get_cross_channel_events(
        self, employee_uid: str, minutes: int = 60
    ) -> dict:
        """Count events across channels for cross-channel correlation."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (e:Employee {uid: $uid})-[]->(event)
                WHERE event.timestamp > datetime() - duration({minutes: $minutes})
                WITH labels(event)[0] AS lbl, event.risk_score AS rs
                RETURN lbl AS channel, count(*) AS cnt,
                       avg(rs) AS avg_risk, max(rs) AS max_risk
                """,
                uid=employee_uid, minutes=minutes,
            )
            return await result.data()

    async def get_open_incidents(self, limit: int = 50) -> list[dict]:
        """Fetch active incidents for the dashboard (open + auto-executed)."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (i:Incident)
                WHERE i.status IN ["open", "investigating"]
                   OR i.action_status IN ["pending", "auto_executed_timeout"]
                OPTIONAL MATCH (e:Employee)-[:INVOLVED_IN]->(i)
                RETURN i.incident_id AS incident_id,
                       i.title AS title,
                       i.severity AS severity,
                       i.score AS score,
                       i.status AS status,
                       i.created_at AS created_at,
                       i.llm_summary AS llm_summary,
                       i.action_proposed AS action_proposed,
                       i.action_status AS action_status,
                       i.operator_note AS operator_note,
                       collect(DISTINCT e.full_name) AS involved
                ORDER BY i.created_at DESC
                LIMIT $limit
                """,
                limit=limit,
            )
            return await result.data()

    async def get_action_log(
        self, limit: int = 100, action_type: str | None = None
    ) -> list[dict]:
        """Full action history for the dashboard log view."""
        where_clause = ""
        params: dict[str, Any] = {"limit": limit}
        if action_type:
            where_clause = "WHERE i.action_proposed = $action_type"
            params["action_type"] = action_type

        async with self._driver.session() as session:
            result = await session.run(
                f"""
                MATCH (i:Incident)
                {where_clause}
                RETURN i.incident_id AS incident_id,
                       i.title AS title,
                       i.severity AS severity,
                       i.action_proposed AS action,
                       i.action_status AS status,
                       i.updated_at AS timestamp,
                       i.operator_note AS note
                ORDER BY i.updated_at DESC
                LIMIT $limit
                """,
                **params,
            )
            return await result.data()

    async def get_incident_subgraph(self, incident_id: str) -> dict:
        """Get full subgraph around an incident for visualization."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (i:Incident {incident_id: $iid})
                OPTIONAL MATCH path = (n)-[*1..2]-(i)
                WITH i, collect(DISTINCT n) AS nodes, collect(DISTINCT path) AS paths
                UNWIND nodes AS node
                RETURN DISTINCT
                    labels(node)[0] AS label,
                    properties(node) AS props,
                    elementId(node) AS id
                """,
                iid=incident_id,
            )
            nodes = await result.data()

            # Get relationships
            result2 = await session.run(
                """
                MATCH (i:Incident {incident_id: $iid})
                OPTIONAL MATCH (n)-[r]-(i)
                OPTIONAL MATCH (n)-[r2]->(n2) WHERE (n2)-[]-(i)
                WITH collect(DISTINCT {
                    source: elementId(startNode(r)), target: elementId(endNode(r)),
                    type: type(r)
                }) + collect(DISTINCT {
                    source: elementId(n), target: elementId(n2),
                    type: type(r2)
                }) AS rels
                UNWIND rels AS rel
                RETURN DISTINCT rel
                """,
                iid=incident_id,
            )
            rels = await result2.data()

            return {"nodes": nodes, "relationships": [r["rel"] for r in rels if r.get("rel")]}

    async def get_stale_pending_incidents(self, timeout_seconds: int) -> list[dict]:
        """Find incidents with action_status='pending' older than timeout_seconds."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (i:Incident)
                WHERE i.action_status = "pending"
                  AND i.updated_at < datetime() - duration({seconds: $timeout})
                OPTIONAL MATCH (e:Employee)-[:INVOLVED_IN]->(i)
                RETURN i.incident_id AS incident_id,
                       i.title AS title,
                       i.severity AS severity,
                       i.score AS score,
                       i.action_proposed AS action_proposed,
                       i.llm_summary AS llm_summary,
                       i.updated_at AS updated_at,
                       collect(DISTINCT e.uid) AS involved_uids,
                       collect(DISTINCT e.full_name) AS involved_names
                ORDER BY i.updated_at ASC
                """,
                timeout=timeout_seconds,
            )
            return await result.data()

    async def update_employee_flag(
        self,
        uid: str,
        flagged: bool = True,
        isolated: bool = False,
        incident_id: str = "",
    ) -> None:
        """Flag/isolate an employee in the graph (autonomous enforcement)."""
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (e:Employee {uid: $uid})
                SET e.flagged = $flagged,
                    e.isolated = $isolated,
                    e.flag_reason = $incident_id,
                    e.flagged_at = datetime()
                """,
                uid=uid, flagged=flagged, isolated=isolated,
                incident_id=incident_id,
            )

    # ══════════════════════════════════════════════════════════════════════════
    # ── Forensic Layer CRUD (Paladin 2.0) ─────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════════════

    async def create_forensic_plan(self, plan: dict) -> str:
        """Create a ForensicPlan node."""
        async with self._driver.session() as session:
            await session.run(
                """
                CREATE (p:ForensicPlan {
                    plan_id:         $plan_id,
                    incident_id:     $incident_id,
                    status:          $status,
                    working_plan:    $working_plan,
                    iteration_count: $iteration_count,
                    max_iterations:  $max_iterations,
                    created_at:      datetime(),
                    updated_at:      datetime(),
                    completion_reason: ""
                })
                """, **plan)
        return plan["plan_id"]

    async def link_plan_to_incident(self, incident_id: str, plan_id: str) -> None:
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (i:Incident {incident_id: $iid}), (p:ForensicPlan {plan_id: $pid})
                MERGE (i)-[:HAS_FORENSIC_PLAN]->(p)
                """, iid=incident_id, pid=plan_id)

    async def create_todo_item(self, item: dict) -> None:
        """Create a TodoItem node linked to its ForensicPlan."""
        async with self._driver.session() as session:
            await session.run(
                """
                CREATE (t:TodoItem {
                    item_id:        $item_id,
                    plan_id:        $plan_id,
                    order_index:    $order_index,
                    description:    $description,
                    status:         $status,
                    result_summary: "",
                    blocked_reason: $blocked_reason,
                    recheck_reason: $recheck_reason,
                    iteration_added: $iteration_added,
                    mcp_function:   $mcp_function,
                    created_at:     datetime()
                })
                WITH t
                MATCH (p:ForensicPlan {plan_id: $plan_id})
                MERGE (p)-[:CONTAINS_TODO]->(t)
                """,
                item_id=item["item_id"],
                plan_id=item["plan_id"],
                order_index=item.get("order_index", 0),
                description=item.get("description", ""),
                status=item.get("status", "PENDING"),
                blocked_reason=item.get("blocked_reason", ""),
                recheck_reason=item.get("recheck_reason", ""),
                iteration_added=item.get("iteration_added", 0),
                mcp_function=item.get("mcp_function", ""),
            )

    async def update_todo_status(self, item_id: str, status: str,
                                 result_summary: str = "",
                                 blocked_reason: str = "") -> None:
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (t:TodoItem {item_id: $item_id})
                SET t.status = $status,
                    t.result_summary = CASE WHEN $summary <> "" THEN $summary ELSE t.result_summary END,
                    t.blocked_reason = CASE WHEN $blocked <> "" THEN $blocked ELSE t.blocked_reason END
                WITH t
                MATCH (p:ForensicPlan {plan_id: t.plan_id})
                SET p.updated_at = datetime()
                """,
                item_id=item_id, status=status,
                summary=result_summary, blocked=blocked_reason)

    async def create_finding(self, finding: dict) -> str:
        """Create a Finding node linked to plan and todo item."""
        async with self._driver.session() as session:
            await session.run(
                """
                CREATE (f:Finding {
                    finding_id:      $finding_id,
                    plan_id:         $plan_id,
                    todo_item_id:    $todo_item_id,
                    description:     $description,
                    evidence_source: $evidence_source,
                    tool_used:       $tool_used,
                    tool_output_hash: $tool_output_hash,
                    confidence:      $confidence,
                    verified:        $verified,
                    verification_method: "",
                    evidence_quote:  $evidence_quote,
                    iteration_number: $iteration_number,
                    created_at:      datetime()
                })
                WITH f
                MATCH (p:ForensicPlan {plan_id: $plan_id})
                MERGE (p)-[:PRODUCED]->(f)
                WITH f
                MATCH (t:TodoItem {item_id: $todo_item_id})
                MERGE (f)-[:PRODUCED_BY]->(t)
                """,
                finding_id=finding["finding_id"],
                plan_id=finding["plan_id"],
                todo_item_id=finding.get("todo_item_id", ""),
                description=finding.get("description", ""),
                evidence_source=finding.get("evidence_source", ""),
                tool_used=finding.get("tool_used", ""),
                tool_output_hash=finding.get("tool_output_hash", ""),
                confidence=finding.get("confidence", 50),
                verified=finding.get("verified", False),
                evidence_quote=finding.get("evidence_quote", ""),
                iteration_number=finding.get("iteration_number", 0),
            )
        return finding["finding_id"]

    async def get_finding(self, finding_id: str) -> dict | None:
        async with self._driver.session() as session:
            result = await session.run(
                "MATCH (f:Finding {finding_id: $fid}) RETURN properties(f) AS props",
                fid=finding_id)
            record = await result.single()
            return dict(record["props"]) if record else None

    async def update_finding_verification(self, finding_id: str,
                                          verified: bool, method: str) -> None:
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (f:Finding {finding_id: $fid})
                SET f.verified = $verified, f.verification_method = $method
                """, fid=finding_id, verified=verified, method=method)

    async def get_findings_for_plan(self, plan_id: str) -> list[dict]:
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (p:ForensicPlan {plan_id: $pid})-[:PRODUCED]->(f:Finding)
                RETURN properties(f) AS props
                ORDER BY f.created_at ASC
                """, pid=plan_id)
            return [dict(r["props"]) for r in await result.data()]

    async def get_plan_with_items(self, plan_id: str) -> dict | None:
        """Get plan + all todo items + findings in one query."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (p:ForensicPlan {plan_id: $pid})
                OPTIONAL MATCH (p)-[:CONTAINS_TODO]->(t:TodoItem)
                OPTIONAL MATCH (p)-[:PRODUCED]->(f:Finding)
                WITH p,
                     collect(DISTINCT properties(t)) AS todos,
                     collect(DISTINCT properties(f)) AS findings
                RETURN properties(p) AS plan, todos, findings
                """, pid=plan_id)
            record = await result.single()
            if not record:
                return None
            plan = dict(record["plan"])
            plan["todo_items"] = [dict(t) for t in record["todos"] if t]
            plan["findings"] = [dict(f) for f in record["findings"] if f]
            return plan

    async def update_plan_status(self, plan_id: str, status: str,
                                 completion_reason: str = "") -> None:
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (p:ForensicPlan {plan_id: $pid})
                SET p.status = $status, p.updated_at = datetime(),
                    p.completion_reason = CASE WHEN $reason <> "" THEN $reason
                                          ELSE p.completion_reason END
                """, pid=plan_id, status=status, reason=completion_reason)

    async def increment_plan_iteration(self, plan_id: str) -> None:
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (p:ForensicPlan {plan_id: $pid})
                SET p.iteration_count = p.iteration_count + 1,
                    p.updated_at = datetime()
                """, pid=plan_id)

    async def create_plan_version(self, plan_id: str) -> None:
        """Create version history snapshot via HAS_VERSION relationship."""
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (p:ForensicPlan {plan_id: $pid})
                CREATE (v:ForensicPlan {
                    plan_id: p.plan_id + "_v" + toString(p.iteration_count),
                    incident_id: p.incident_id,
                    status: p.status,
                    working_plan: p.working_plan,
                    iteration_count: p.iteration_count,
                    max_iterations: p.max_iterations,
                    created_at: p.created_at,
                    updated_at: datetime(),
                    is_version: true
                })
                MERGE (p)-[:HAS_VERSION]->(v)
                """, pid=plan_id)

    async def add_contradicts_edge(self, finding_a: str, finding_b: str,
                                   description: str,
                                   contradiction_type: str) -> None:
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (a:Finding {finding_id: $a}), (b:Finding {finding_id: $b})
                MERGE (a)-[:CONTRADICTS {
                    description: $desc,
                    contradiction_type: $ctype,
                    detected_at: datetime()
                }]->(b)
                """, a=finding_a, b=finding_b,
                desc=description, ctype=contradiction_type)

    async def get_contradictions_for_plan(self, plan_id: str) -> list[dict]:
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (p:ForensicPlan {plan_id: $pid})-[:PRODUCED]->(a:Finding)
                      -[c:CONTRADICTS]->(b:Finding)
                RETURN a.finding_id AS finding_a, b.finding_id AS finding_b,
                       c.description AS description,
                       c.contradiction_type AS contradiction_type
                """, pid=plan_id)
            return await result.data()

    async def get_forensic_plan_for_incident(self, incident_id: str) -> dict | None:
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (i:Incident {incident_id: $iid})-[:HAS_FORENSIC_PLAN]->(p:ForensicPlan)
                WHERE NOT p.is_version
                RETURN p.plan_id AS plan_id
                ORDER BY p.created_at DESC LIMIT 1
                """, iid=incident_id)
            record = await result.single()
            if record:
                return await self.get_plan_with_items(record["plan_id"])
            return None

