from enum import Enum


class Role(str, Enum):
    """The four prototype roles (see docs/authorization-design.md).

    writer  - can create audit events.
    reader  - can query audit events (automatically scoped to their own
              tenant - see app.api.routes.audit_events).
    auditor - can query events, verify the chain, export audit data, and
              view compliance reports, across all tenants.
    admin   - can perform all operations, including retention and
              redaction.
    """

    WRITER = "writer"
    READER = "reader"
    AUDITOR = "auditor"
    ADMIN = "admin"
