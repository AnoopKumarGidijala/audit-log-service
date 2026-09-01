# Assumptions

This document captures assumptions and open decisions for the project. Items here are not finalized and may change as the design is worked out.

## Open / Not Finalized

- **Storage backend:** Not yet decided (e.g. relational database, embedded store, or other).
- **Hash algorithm:** Not yet decided (e.g. SHA-256 or an alternative).
- **Authentication / authorization model:** Not yet decided for the write, query, and verification APIs.
- **Redaction mechanism:** Not yet decided how redaction will interact with the hash chain without invalidating tamper evidence.
- **Retention policy specifics:** Not yet decided (e.g. fixed duration, configurable per event type, archival vs. deletion).
- **Export format:** Not yet decided (e.g. JSON, CSV, or a signed/structured format).
- **Compliance report format and scope:** Not yet decided.
- **Deployment/runtime environment:** Not yet decided.
