#!/usr/bin/env python3
"""
================================================================================
QUERY PARSING & FILTER RESOLUTION LAYER
================================================================================
Author: Principal Forensics Specialist & Data Systems Architect
Description:
    Transforms natural language forensic queries into structured filter objects
    and routing intents. Bridges the gap between investigative questions and
    downstream retrieval:

    Pipeline Flow:
      1. Natural Language Query
         -> Query Parser (query_parser.py)
         -> Structured QueryFilter Object
      2. Structured QueryFilter
         -> Pass 1: Vector Pre-Filter (semantic_query + source_type + level + event_id) -> Qdrant
         -> Pass 2: Instance Narrowing (time_range + entity_filters) -> DuckDB template_instances
         -> Pass 3: Correlation Dispatch (if intent == 'correlation') -> Correlation Index
         -> Canonical Fetch -> Full untouched records from DuckDB

    Hard Constraints:
      - Zero False-Narrowing: Generic terms (error, issue, what happened) keep
        source_type as None rather than guessing.
      - Explicit UTC Bounds: All relative time expressions (yesterday, last week,
        around 3pm) resolve to audited, absolute ISO 8601 UTC bounds.
      - Auditability: Full provenance of parsed filters and residual semantic query.
================================================================================
"""

from __future__ import annotations

import calendar
import datetime
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from dateutil import parser as date_parser

logger = logging.getLogger("DFIR_QueryParser")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ==============================================================================
# 1. DATA STRUCTURES
# ==============================================================================

@dataclass
class TimeRange:
    """Explicit UTC bounding window for temporal filtering and forensic auditability."""
    start_utc: str
    end_utc: str
    is_relative: bool = False
    raw_expression: str = ""
    outside_coverage: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EntityFilters:
    """Forensic entity identifiers extracted from query."""
    process_id: Optional[str] = None
    thread_id: Optional[str] = None
    user_id: Optional[str] = None
    logon_id: Optional[str] = None
    computer: Optional[str] = None
    ip_address: Optional[str] = None
    event_record_id: Optional[str] = None
    process_name: Optional[str] = None
    provider: Optional[str] = None
    status_code: Optional[str] = None

    def has_any(self) -> bool:
        return any(v is not None for v in asdict(self).values())

    def to_dict(self) -> Dict[str, Optional[str]]:
        return asdict(self)


@dataclass
class QueryFilter:
    """Complete structured filter and intent object passed downstream."""
    time_range: Optional[TimeRange]
    source_type: Optional[str]  # "Application" | "System" | "Security" | None
    entity_filters: EntityFilters
    event_id: Optional[str]
    level: Optional[str]  # "Information" | "Warning" | "Error" | "Critical" | None
    semantic_query: str
    intent: str  # "specific_instance" | "pattern_or_aggregate" | "correlation" | "ambiguous"
    raw_query: str
    clarifying_question: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        if self.time_range:
            res["time_range"] = self.time_range.to_dict()
        res["entity_filters"] = self.entity_filters.to_dict()
        return res


# ==============================================================================
# 2. FORENSIC TAXONOMIES & LOOKUP TABLES
# ==============================================================================

# Explicit Windows Event ID phrase mapping
EVENT_PHRASE_TO_ID: List[Tuple[re.Pattern, str, str]] = [
    # (regex_pattern, event_id, canonical_source_type)
    (re.compile(r"\b(?:failed\s+logon|logon\s+failure|failed\s+login|login\s+failure)\b", re.I), "4625", "Security"),
    (re.compile(r"\b(?:successful\s+logon|logon\s+success(?:ful)?|successful\s+login|login\s+success)\b", re.I), "4624", "Security"),
    (re.compile(r"\b(?:logoff|logged\s+off|user\s+logoff)\b", re.I), "4634", "Security"),
    (re.compile(r"\b(?:explicit\s+credentials|logon\s+with\s+explicit)\b", re.I), "4648", "Security"),
    (re.compile(r"\b(?:special\s+privileges\s+assigned|privileged\s+logon)\b", re.I), "4672", "Security"),
    (re.compile(r"\b(?:new\s+process(?:\s+created)?|process\s+creation|process\s+started)\b", re.I), "4688", "Security"),
    (re.compile(r"\b(?:process\s+terminated|process\s+exited)\b", re.I), "4689", "Security"),
    (re.compile(r"\b(?:user\s+account\s+created|created\s+user\s+account)\b", re.I), "4720", "Security"),
    (re.compile(r"\b(?:account\s+lock(?:out|ed)?|user\s+locked\s+out)\b", re.I), "4740", "Security"),
    (re.compile(r"\b(?:password\s+reset(?:\s+attempt)?|reset\s+password)\b", re.I), "4724", "Security"),
    (re.compile(r"\b(?:audit\s+log\s+cleared|event\s+log\s+cleared|audit\s+cleared)\b", re.I), "1102", "Security"),
    (re.compile(r"\b(?:new\s+service\s+installed|service\s+installation)\b", re.I), "7045", "System"),
    (re.compile(r"\b(?:service\s+state\s+changed|service\s+running\s+state|service\s+stopped|service\s+started)\b", re.I), "7036", "System"),
    (re.compile(r"\b(?:unexpected\s+shutdown|dirty\s+shutdown)\b", re.I), "6008", "System"),
    (re.compile(r"\b(?:application\s+crash|app\s+crash|application\s+error|app\s+hang|application\s+hang)\b", re.I), "1000", "Application"),
]

# Strict channel identifiers (only clear indicators, never vague terms)
CHANNEL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:security(?:\s+(?:log|event|channel|audit))?|logon|login|kerberos|ntlm|privilege)\b", re.I), "Security"),
    (re.compile(r"\b(?:system(?:\s+(?:log|event|channel|error))|service\s+control\s+manager|scm|driver\s+fault|bsod|blue\s+screen)\b", re.I), "System"),
    (re.compile(r"\b(?:application(?:\s+(?:log|event|channel|crash|error))|app\s+crash|wer|drwatson)\b", re.I), "Application"),
]


# ==============================================================================
# 3. COMPONENT PARSERS
# ==============================================================================

class TimeExpressionResolver:
    """Resolves relative and absolute temporal expressions into explicit UTC bounds."""

    @staticmethod
    def resolve(
        text: str,
        reference_time: Optional[datetime.datetime] = None,
        data_bounds: Optional[Tuple[str, str]] = None,
    ) -> Tuple[Optional[TimeRange], str]:
        """Parses time expressions from query text.

        Returns:
            Tuple of (TimeRange or None, residual_text_with_time_removed)
        """
        ref = reference_time
        if ref is None and data_bounds and len(data_bounds) > 1 and data_bounds[1]:
            try:
                ref = date_parser.parse(str(data_bounds[1]))
            except Exception:
                ref = None
        if ref is None:
            ref = datetime.datetime.now(datetime.timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=datetime.timezone.utc)

        clean_text = text
        start_dt: Optional[datetime.datetime] = None
        end_dt: Optional[datetime.datetime] = None
        is_relative = False
        raw_expr = ""

        # 1. Check for combined time-of-day + relative day (e.g. "around 3pm yesterday", "at 15:30 today")
        combo_match = re.search(
            r"\b(?:around|about|approx(?:imately)?|at)\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s+(yesterday|today)\b",
            clean_text,
            re.I,
        )
        if combo_match:
            raw_expr = combo_match.group(0)
            hr = int(combo_match.group(1))
            mn = int(combo_match.group(2) or 0)
            meridiem = (combo_match.group(3) or "").lower()
            rel_day = combo_match.group(4).lower()

            if meridiem == "pm" and hr < 12:
                hr += 12
            elif meridiem == "am" and hr == 12:
                hr = 0

            target_date = (ref - datetime.timedelta(days=1)).date() if rel_day == "yesterday" else ref.date()
            center_dt = datetime.datetime(target_date.year, target_date.month, target_date.day, hr, mn, tzinfo=datetime.timezone.utc)
            # Window of +/- 30 minutes around target time
            start_dt = center_dt - datetime.timedelta(minutes=30)
            end_dt = center_dt + datetime.timedelta(minutes=30)
            is_relative = True
            clean_text = clean_text.replace(raw_expr, " ")

        # 2. Check for standalone "around 3pm" / "at 15:00"
        if not start_dt:
            around_match = re.search(
                r"\b(?:around|about|approx(?:imately)?|at)\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b",
                clean_text,
                re.I,
            )
            if around_match:
                raw_expr = around_match.group(0)
                hr = int(around_match.group(1))
                mn = int(around_match.group(2) or 0)
                meridiem = (around_match.group(3) or "").lower()

                if meridiem == "pm" and hr < 12:
                    hr += 12
                elif meridiem == "am" and hr == 12:
                    hr = 0

                center_dt = datetime.datetime(ref.year, ref.month, ref.day, hr, mn, tzinfo=datetime.timezone.utc)
                start_dt = center_dt - datetime.timedelta(minutes=30)
                end_dt = center_dt + datetime.timedelta(minutes=30)
                is_relative = True
                clean_text = clean_text.replace(raw_expr, " ")

        # 3. Relative Day Expressions: "yesterday", "today"
        if not start_dt:
            day_match = re.search(r"\b(yesterday|today)\b", clean_text, re.I)
            if day_match:
                raw_expr = day_match.group(1)
                is_relative = True
                if raw_expr.lower() == "yesterday":
                    target_date = (ref - datetime.timedelta(days=1)).date()
                else:
                    target_date = ref.date()

                start_dt = datetime.datetime(target_date.year, target_date.month, target_date.day, 0, 0, 0, tzinfo=datetime.timezone.utc)
                end_dt = datetime.datetime(target_date.year, target_date.month, target_date.day, 23, 59, 59, 999999, tzinfo=datetime.timezone.utc)
                clean_text = re.sub(r"\b" + re.escape(raw_expr) + r"\b", " ", clean_text, flags=re.I)

        # 4. Relative Duration Expressions: "last week", "past week", "last 24 hours", "last 7 days", "past hour"
        if not start_dt:
            dur_match = re.search(
                r"\b(?:last|past)\s+(week|month|\d+\s*(?:hours?|days?|minutes?|weeks?))\b",
                clean_text,
                re.I,
            )
            if dur_match:
                raw_expr = dur_match.group(0)
                is_relative = True
                dur_str = dur_match.group(1).lower()

                if "week" in dur_str and not any(c.isdigit() for c in dur_str):
                    delta = datetime.timedelta(days=7)
                elif "month" in dur_str and not any(c.isdigit() for c in dur_str):
                    delta = datetime.timedelta(days=30)
                else:
                    num_match = re.search(r"\d+", dur_str)
                    num = int(num_match.group(0)) if num_match else 1
                    if "hour" in dur_str:
                        delta = datetime.timedelta(hours=num)
                    elif "day" in dur_str:
                        delta = datetime.timedelta(days=num)
                    elif "minute" in dur_str:
                        delta = datetime.timedelta(minutes=num)
                    elif "week" in dur_str:
                        delta = datetime.timedelta(weeks=num)
                    else:
                        delta = datetime.timedelta(days=7)

                start_dt = ref - delta
                end_dt = ref
                clean_text = clean_text.replace(raw_expr, " ")

        # 5. Explicit Calendar Dates: "on May 7th", "on 2026-09-14", "on 2026-09-14 14:00"
        if not start_dt:
            cal_match = re.search(
                r"\bon\s+([A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?(?:\s*,\s*\d{4})?|\d{4}-\d{2}-\d{2})\b",
                clean_text,
                re.I,
            )
            if cal_match:
                raw_expr = cal_match.group(0)
                date_str = cal_match.group(1)
                # Strip ordinals (st, nd, rd, th)
                clean_date_str = re.sub(r"(\d+)(st|nd|rd|th)", r"\1", date_str, flags=re.I)
                try:
                    parsed = date_parser.parse(clean_date_str, default=datetime.datetime(ref.year, 1, 1))
                    start_dt = datetime.datetime(parsed.year, parsed.month, parsed.day, 0, 0, 0, tzinfo=datetime.timezone.utc)
                    end_dt = datetime.datetime(parsed.year, parsed.month, parsed.day, 23, 59, 59, 999999, tzinfo=datetime.timezone.utc)
                    clean_text = clean_text.replace(raw_expr, " ")
                except Exception:
                    pass

        # 6. Explicit Between / Range Expressions: "between X and Y"
        if not start_dt:
            between_match = re.search(
                r"\bbetween\s+(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}(?::\d{2})?)\s+and\s+(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}(?::\d{2})?)\b",
                clean_text,
                re.I,
            )
            if between_match:
                raw_expr = between_match.group(0)
                try:
                    p1 = date_parser.parse(between_match.group(1))
                    p2 = date_parser.parse(between_match.group(2))
                    start_dt = p1.replace(tzinfo=datetime.timezone.utc)
                    end_dt = p2.replace(tzinfo=datetime.timezone.utc)
                    clean_text = clean_text.replace(raw_expr, " ")
                except Exception:
                    pass

        if not start_dt or not end_dt:
            return None, clean_text

        # Format bounds to strict UTC ISO 8601 strings
        start_utc = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_utc = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Check coverage clamping if data_bounds provided
        outside_coverage = False
        if data_bounds:
            data_start, data_end = data_bounds
            if end_utc < data_start or start_utc > data_end:
                outside_coverage = True

        time_range = TimeRange(
            start_utc=start_utc,
            end_utc=end_utc,
            is_relative=is_relative,
            raw_expression=raw_expr.strip(),
            outside_coverage=outside_coverage,
        )
        return time_range, clean_text


class ForensicEntityExtractor:
    """Extracts granular technical entities (process ID, user, IP, logon ID, host, process name, provider, status code)."""

    @staticmethod
    def extract(text: str) -> Tuple[EntityFilters, str]:
        clean_text = text
        pid: Optional[str] = None
        tid: Optional[str] = None
        uid: Optional[str] = None
        lid: Optional[str] = None
        comp: Optional[str] = None
        ip: Optional[str] = None
        rec_id: Optional[str] = None
        proc_name: Optional[str] = None
        prov: Optional[str] = None
        status_code: Optional[str] = None

        # 1. Process ID: "process 1064", "process id 1064", "pid 1064", "pid:1064", "process 0x428"
        pid_match = re.search(r"\b(?:process|proc|pid)(?:\s*(?:id|#))?\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)\b", clean_text, re.I)
        if pid_match:
            pid = pid_match.group(1)
            clean_text = clean_text.replace(pid_match.group(0), " ")

        # 2. Process Name: e.g. "process powershell.exe", "image lsass.exe", "process svchost.exe"
        pname_match = re.search(
            r"\b(?:process(?:\s*name)?|image(?:\s*name)?|executable|app(?:lication)?)\s*(?:is|was|called|named|[:=])?\s*([A-Za-z0-9_.\-]+\.(?:exe|dll|sys|bin|scr))\b",
            clean_text,
            re.I,
        )
        if pname_match:
            proc_name = pname_match.group(1)
            clean_text = clean_text.replace(pname_match.group(0), " ")
        else:
            # Standalone .exe mention: "for powershell.exe", "running cmd.exe"
            exe_match = re.search(r"\b([A-Za-z0-9_.\-]+\.exe)\b", clean_text, re.I)
            if exe_match:
                cand_exe = exe_match.group(1)
                proc_name = cand_exe
                clean_text = clean_text.replace(cand_exe, " ")

        # 3. Thread ID: "thread 4412", "thread id 4412", "tid 4412"
        tid_match = re.search(r"\b(?:thread|tid)(?:\s*(?:id|#))?\s*[:=]?\s*(\d+)\b", clean_text, re.I)
        if tid_match:
            tid = tid_match.group(1)
            clean_text = clean_text.replace(tid_match.group(0), " ")

        # 4. IP Address (IPv4): e.g. 192.168.1.50
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean_text)
        if ip_match:
            ip = ip_match.group(0)
            clean_text = clean_text.replace(ip, " ")

        # 5. Status / Error Code: "status 0xC000006D", "error code 0x80070005"
        status_match = re.search(r"\b(?:status(?:\s*code)?|error\s*code|substatus)\s*[:=]?\s*(0x[0-9a-fA-F]+)\b", clean_text, re.I)
        if status_match:
            status_code = status_match.group(1)
            clean_text = clean_text.replace(status_match.group(0), " ")

        # 6. Logon ID: "logon id 0x12a4b", "logon id 999"
        lid_match = re.search(r"\blogon\s*(?:id|#)?\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)\b", clean_text, re.I)
        if lid_match:
            lid = lid_match.group(1)
            clean_text = clean_text.replace(lid_match.group(0), " ")

        # 7. User ID / SID / Username:
        sid_match = re.search(r"\b(S-1-[0-59]-\d+(?:-\d+)+)\b", clean_text)
        if sid_match:
            uid = sid_match.group(1)
            clean_text = clean_text.replace(uid, " ")
        else:
            # Matches "user is SYSTEM", "user Administrator", "username: jsmith", "user NT AUTHORITY\SYSTEM"
            user_stopwords_pat = r'(?:is|was|called|named|for|the|a|an|logon|login|failure|success|event|events|error|name|account|id|user|users|status|who|which|where|with|from|at|in)'
            u_match = re.search(
                r'\b(?:user(?:name)?|account)(?:\s*name)?(?:\s+(?:is|was|called|named|for|where|with|from|[:=]))*\s*[:=]?\s*(?!' + user_stopwords_pat + r'\b)([A-Za-z0-9_.\-\\\\]+)\b',
                clean_text,
                re.I,
            )
            if u_match:
                uid = u_match.group(1)
                clean_text = clean_text.replace(u_match.group(0), " ")

        # 8. Computer / Hostname:
        comp_stopwords_pat = r'(?:is|was|called|named|on|where|with|from|in|at|the|a|an|name|local|remote|server|machine|computer|host|workstation|id|log|which)'
        comp_match = re.search(
            r'\b(?:computer|machine|host|workstation)(?:\s*name)?(?:\s+(?:is|was|called|named|on|where|in|from|[:=]))*\s*[:=]?\s*(?!' + comp_stopwords_pat + r'\b)([A-Za-z0-9_.\-]+)\b',
            clean_text,
            re.I,
        )
        if comp_match:
            comp = comp_match.group(1)
            clean_text = clean_text.replace(comp_match.group(0), " ")

        # 9. Provider: "provider Service Control Manager", "from provider X"
        prov_match = re.search(
            r"\b(?:provider|source)\s*(?:is|was|called|named|[:=])?\s*([A-Za-z0-9\-_. ]+?)(?=(?:\s+(?:log|events?|in|on|with|for)\b|$))",
            clean_text,
            re.I,
        )
        if prov_match:
            cand_prov = prov_match.group(1).strip()
            prov_stopwords = {"is", "was", "called", "named", "the", "a", "an", "name", "log", "events", "from", "where"}
            if cand_prov.lower() not in prov_stopwords and len(cand_prov) > 2:
                prov = cand_prov
                clean_text = clean_text.replace(prov_match.group(0), " ")

        # 10. Event Record ID: "event record id 4120", "record REC_00120"
        rec_match = re.search(r"\b(?:event\s*record\s*id|record\s*id|record)\s*[:=]?\s*(REC_\d+|\d+)\b", clean_text, re.I)
        if rec_match:
            rec_id = rec_match.group(1)
            clean_text = clean_text.replace(rec_match.group(0), " ")

        entities = EntityFilters(
            process_id=pid,
            thread_id=tid,
            user_id=uid,
            logon_id=lid,
            computer=comp,
            ip_address=ip,
            event_record_id=rec_id,
            process_name=proc_name,
            provider=prov,
            status_code=status_code,
        )
        return entities, clean_text


class ChannelClassifier:
    """Classifies source_type with strict zero-false-narrowing guarantees."""

    @staticmethod
    def classify(text: str) -> Optional[str]:
        """Returns 'Security', 'System', 'Application', or None if ambiguous/vague."""
        for pattern, channel in CHANNEL_PATTERNS:
            if pattern.search(text):
                return channel
        return None


class EventIdResolver:
    """Resolves explicit event IDs or known Windows Event ID phrases."""

    @staticmethod
    def resolve(text: str) -> Tuple[Optional[str], Optional[str], str]:
        """Returns Tuple of (event_id, channel_hint, residual_text)."""
        clean_text = text

        # 1. Check explicit Event ID: "event 4625", "event id 4624"
        id_match = re.search(r"\bevent\s*(?:id|#)?\s*[:=]?\s*(\d+)\b", clean_text, re.I)
        if id_match:
            eid = id_match.group(1)
            clean_text = clean_text.replace(id_match.group(0), " ")
            return eid, None, clean_text

        # 2. Check phrase taxonomy
        for pattern, eid, channel in EVENT_PHRASE_TO_ID:
            if pattern.search(clean_text):
                return eid, channel, clean_text

        return None, None, clean_text


class SeverityLevelResolver:
    """Resolves event severity/level from query mentions with audit-awareness."""

    @staticmethod
    def resolve(
        text: str,
        source_type: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> Optional[str]:
        if re.search(r"\b(?:critical|fatal)\b", text, re.I):
            return "Critical"

        # Explicit level request: "level error", "severity error", "error level"
        explicit_error = bool(re.search(r"\b(?:severity\s+error|level\s+error|error\s+level)\b", text, re.I))

        # Check if query is a Security audit event where LevelName is LogAlways
        is_security_audit = (
            (source_type and str(source_type).lower() == "security") or
            (event_id and str(event_id) in ("4624", "4625", "4634", "4648", "4672", "4688", "4689", "4720", "4740", "4724", "1102"))
        )

        if re.search(r"\b(?:error|errors|fault|crash)\b", text, re.I):
            return "Error"

        if re.search(r"\b(?:failed|failure)\b", text, re.I):
            # If it's a Security audit event (e.g. logon failure) without explicit level error requested, don't force Error level
            if is_security_audit and not explicit_error:
                return None
            return "Error"

        if re.search(r"\b(?:warning|warn)\b", text, re.I):
            return "Warning"
        if re.search(r"\b(?:info|information|informational)\b", text, re.I):
            return "Information"
        return None


# ==============================================================================
# 4. MAIN QUERY PARSER PIPELINE
# ==============================================================================

class ForensicQueryParser:
    """End-to-End Forensic Query Parser and Filter Resolution Engine.

    Parses natural language query strings into structured QueryFilter objects
    complete with UTC time bounds, entity filters, strict channel mappings,
    event ID resolution, and intent classification.
    """

    def __init__(self):
        self.time_resolver = TimeExpressionResolver()
        self.entity_extractor = ForensicEntityExtractor()
        self.channel_classifier = ChannelClassifier()
        self.event_resolver = EventIdResolver()
        self.severity_resolver = SeverityLevelResolver()

    def classify_intent(
        self,
        raw_query: str,
        time_range: Optional[TimeRange],
        entities: EntityFilters,
        event_id: Optional[str],
    ) -> Tuple[str, Optional[str]]:
        """Classifies query intent into:
          - 'correlation'
          - 'pattern_or_aggregate'
          - 'specific_instance'
          - 'ambiguous'

        Returns:
            Tuple of (intent_string, optional_clarifying_question)
        """
        lower_q = raw_query.lower()

        # 1. Correlation intent: references temporal proximity to an anchor or causality
        corr_patterns = [
            r"what\s+else\s+happened(?:\s+around|\s+at|\s+during)?",
            r"around\s+the\s+time\s+of",
            r"what\s+happened\s+(?:before|after|right\s+after)",
            r"did\s+this\s+cause",
            r"correlated\s+with",
            r"related\s+events?",
            r"timeline\s+around",
        ]
        if any(re.search(p, lower_q) for p in corr_patterns):
            return "correlation", None

        # 2. Pattern or Aggregate intent: asks for frequency, existence, counts, trends
        agg_patterns = [
            r"\bhow\s+often\b",
            r"\bhow\s+many\b",
            r"\bdid\s+(?:the\s+)?.*\sever\b",
            r"\bfrequency\s+of\b",
            r"\bcount\s+of\b",
            r"\btrend\b",
            r"\bhow\s+common\b",
            r"\ball\s+occurrences\b",
        ]
        has_agg_indicator = any(re.search(p, lower_q) for p in agg_patterns)
        if has_agg_indicator and not entities.has_any():
            return "pattern_or_aggregate", None

        # 3. Specific Instance intent: enough signals to narrow to a specific event
        has_specific_signals = (
            entities.has_any() or
            (time_range is not None and (event_id is not None or "show me the" in lower_q or "find this" in lower_q))
        )
        if has_specific_signals:
            return "specific_instance", None

        # If aggregate phrasing is combined with time/entities
        if has_agg_indicator:
            return "pattern_or_aggregate", None

        # 4. Ambiguous intent: lacks narrowing signals but isn't explicitly aggregate
        clarifying_q = (
            "Your query could match multiple events. Would you like to narrow down by "
            "a specific time window (e.g. 'around 3pm yesterday') or specific entity (e.g. user, process ID)?"
        )
        return "ambiguous", clarifying_q

    def parse_query(
        self,
        query: str,
        reference_time: Optional[datetime.datetime] = None,
        data_bounds: Optional[Tuple[str, str]] = None,
    ) -> QueryFilter:
        """Parses a natural language query into a structured QueryFilter object.

        Args:
            query: Raw user query string.
            reference_time: Optional UTC datetime for relative time expressions.
            data_bounds: Optional tuple (start_utc, end_utc) of available dataset coverage.

        Returns:
            Structured QueryFilter instance.
        """
        raw_query = (query or "").strip()
        working_text = raw_query

        # 1. Resolve Time Expression (anchors to data_bounds if reference_time omitted)
        time_range, working_text = self.time_resolver.resolve(
            working_text,
            reference_time=reference_time,
            data_bounds=data_bounds,
        )

        # 2. Extract Technical Entities
        entities, working_text = self.entity_extractor.extract(working_text)

        # 3. Resolve Event ID & Channel Hint
        event_id, channel_hint, working_text = self.event_resolver.resolve(working_text)

        # 4. Classify Source Channel (Strict zero-false-narrowing)
        source_type = self.channel_classifier.classify(raw_query) or channel_hint

        # 5. Resolve Severity Level (aware of audit events)
        level = self.severity_resolver.resolve(raw_query, source_type=source_type, event_id=event_id)

        # 6. Classify Intent
        intent, clarifying_q = self.classify_intent(
            raw_query=raw_query,
            time_range=time_range,
            entities=entities,
            event_id=event_id,
        )

        # 7. Clean Residual Semantic Query
        # Remove noisy filler words from semantic residual
        fillers = [
            r"\b(?:show\s+me|find|get|display|list|tell\s+me|check)\b",
            r"\b(?:please|the|a|an|for|of|on|in|around|about|at|did|ever|how|often|many|times)\b",
            r"\b(?:event|events|log|logs|record|records)\b",
            r"\b(?:what|occurred|happened|occurrences?)\b",
            r"\b(?:where|which|who|with|level|severity|source|channel)\b",
        ]
        semantic_text = working_text
        for f in fillers:
            semantic_text = re.sub(f, " ", semantic_text, flags=re.I)

        # Clean multiple spaces and punctuation
        semantic_query = " ".join(re.sub(r"[^\w\s\-\.]", " ", semantic_text).split()).strip()

        # If semantic query became empty, fallback to non-stopword query tokens or raw_query
        if not semantic_query:
            semantic_query = raw_query

        return QueryFilter(
            time_range=time_range,
            source_type=source_type,
            entity_filters=entities,
            event_id=event_id,
            level=level,
            semantic_query=semantic_query,
            intent=intent,
            raw_query=raw_query,
            clarifying_question=clarifying_q,
        )

    parse = parse_query


# ==============================================================================
# 5. MODULE CONVENIENCE FUNCTION
# ==============================================================================

_GLOBAL_PARSER = ForensicQueryParser()


def parse_forensic_query(
    query: str,
    reference_time: Optional[datetime.datetime] = None,
    data_bounds: Optional[Tuple[str, str]] = None,
) -> QueryFilter:
    """Convenience functional interface to parse forensic queries."""
    return _GLOBAL_PARSER.parse_query(
        query=query,
        reference_time=reference_time,
        data_bounds=data_bounds,
    )
