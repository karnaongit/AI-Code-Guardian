"""
Domain-Default Business Policies Generator
=========================================
When no explicit requirement document is supplied or auto-discovered,
the platform uses the detected business domain to generate implicit,
standard machine-checkable business policies.
"""
from __future__ import annotations

from guardian.policies.models import (
    BusinessPolicy, ControlType, PolicyPriority, PolicySet,
)

DOMAIN_DEFAULT_POLICIES: dict[str, list[dict]] = {
    "Banking / FinTech": [
        {
            "action": "refund",
            "required_control": ControlType.AUTHORIZATION,
            "control_detail": "authorization check",
            "source_text": "Financial refund and disburse operations must require authorization.",
            "priority": PolicyPriority.HIGH,
        },
        {
            "action": "transfer",
            "required_control": ControlType.AUTHORIZATION,
            "control_detail": "permission check",
            "source_text": "Account money transfer operations require authorization and user permission.",
            "priority": PolicyPriority.HIGH,
        },
        {
            "action": "payment",
            "required_control": ControlType.AUDIT,
            "control_detail": "audit log",
            "source_text": "All payment and transaction operations must write an audit log.",
            "priority": PolicyPriority.HIGH,
        },
        {
            "action": "save",
            "required_control": ControlType.VALIDATION,
            "control_detail": "input validation",
            "source_text": "Database persistence operations must validate parameters.",
            "priority": PolicyPriority.MEDIUM,
        },
    ],
    "Retail / E-commerce": [
        {
            "action": "refund",
            "required_control": ControlType.AUTHORIZATION,
            "control_detail": "authorization check",
            "source_text": "Customer refund and payout operations must require authorization.",
            "priority": PolicyPriority.HIGH,
        },
        {
            "action": "checkout",
            "required_control": ControlType.AUDIT,
            "control_detail": "audit log",
            "source_text": "Checkout and order processing must record audit trail.",
            "priority": PolicyPriority.MEDIUM,
        },
        {
            "action": "order",
            "required_control": ControlType.VALIDATION,
            "control_detail": "input validation",
            "source_text": "Order creation must validate pricing and inventory input parameters.",
            "priority": PolicyPriority.MEDIUM,
        },
    ],
    "Healthcare": [
        {
            "action": "record",
            "required_control": ControlType.AUTHORIZATION,
            "control_detail": "authorization check",
            "source_text": "Accessing and modifying patient medical records requires authorization.",
            "priority": PolicyPriority.CRITICAL,
        },
        {
            "action": "patient",
            "required_control": ControlType.AUDIT,
            "control_detail": "audit log",
            "source_text": "Patient data modifications must be logged for audit purposes.",
            "priority": PolicyPriority.HIGH,
        },
        {
            "action": "prescription",
            "required_control": ControlType.ENCRYPTION,
            "control_detail": "encryption",
            "source_text": "Protected health information (PHI) must be encrypted.",
            "priority": PolicyPriority.HIGH,
        },
    ],
    "Cybersecurity": [
        {
            "action": "login",
            "required_control": ControlType.RATE_LIMIT,
            "control_detail": "rate limit",
            "source_text": "Authentication endpoints must implement rate limiting.",
            "priority": PolicyPriority.HIGH,
        },
        {
            "action": "password",
            "required_control": ControlType.ENCRYPTION,
            "control_detail": "strong hashing/encryption",
            "source_text": "Passwords and secrets must be hashed/encrypted securely.",
            "priority": PolicyPriority.CRITICAL,
        },
        {
            "action": "admin",
            "required_control": ControlType.AUTHORIZATION,
            "control_detail": "role-based authorization",
            "source_text": "Administrative operations require role-based access control.",
            "priority": PolicyPriority.HIGH,
        },
    ],
    "SaaS / Platform": [
        {
            "action": "delete",
            "required_control": ControlType.AUTHORIZATION,
            "control_detail": "authorization check",
            "source_text": "Resource deletion operations must require authorization.",
            "priority": PolicyPriority.HIGH,
        },
        {
            "action": "user",
            "required_control": ControlType.AUDIT,
            "control_detail": "audit log",
            "source_text": "User account modifications must record audit logs.",
            "priority": PolicyPriority.MEDIUM,
        },
        {
            "action": "api",
            "required_control": ControlType.RATE_LIMIT,
            "control_detail": "rate limit",
            "source_text": "API endpoints must enforce rate limits.",
            "priority": PolicyPriority.MEDIUM,
        },
    ],
    "General": [
        {
            "action": "save",
            "required_control": ControlType.AUTHORIZATION,
            "control_detail": "authorization check",
            "source_text": "State-changing persistence operations must require authorization.",
            "priority": PolicyPriority.MEDIUM,
        },
        {
            "action": "update",
            "required_control": ControlType.AUDIT,
            "control_detail": "audit log",
            "source_text": "Data updates must be logged for audit purposes.",
            "priority": PolicyPriority.MEDIUM,
        },
        {
            "action": "execute",
            "required_control": ControlType.VALIDATION,
            "control_detail": "input validation",
            "source_text": "Execution commands must validate input arguments.",
            "priority": PolicyPriority.MEDIUM,
        },
    ],
}


def get_domain_default_policy_set(domain: str) -> PolicySet:
    """Generate a PolicySet with standard default business policies for a given domain."""
    specs = DOMAIN_DEFAULT_POLICIES.get(domain) or DOMAIN_DEFAULT_POLICIES["General"]
    policies: list[BusinessPolicy] = []
    doc_name = f"implicit_domain_policy_{domain.lower().replace(' ', '_').replace('/', '_')}"

    for spec in specs:
        p = BusinessPolicy(
            action=spec["action"],
            required_control=spec["required_control"],
            control_detail=spec["control_detail"],
            source_text=spec["source_text"],
            source_document=doc_name,
            priority=spec.get("priority", PolicyPriority.HIGH),
        )
        policies.append(p)

    return PolicySet(policies=policies, documents=[doc_name])
