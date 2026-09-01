# Requirements

This document summarizes the main requirements for the tamper-evident audit log service.

## 1. Append-Only Audit Events

Audit events, once written, must not be modifiable or deletable through normal service operation. The log behaves as an append-only sequence of records.

## 2. Write API

An API for submitting new audit events to the log.

## 3. Query API with Filters

An API for retrieving audit events, supporting filtering (e.g. by time range, actor, event type, or other relevant fields).

## 4. Pagination

Query results must be paginated rather than returned in full, to support large result sets.

## 5. Hash-Chain Tamper Evidence

Each audit event is cryptographically linked to the previous event (e.g. via a hash chain), so that any modification, deletion, or reordering of past events can be detected.

## 6. Verification Endpoint

An endpoint that verifies the integrity of the log (or a portion of it) by validating the hash chain, and reports whether tampering is detected.

## 7. Retention

Support for defining and enforcing how long audit events are retained before they become eligible for removal or archival.

## 8. Redaction

Support for redacting sensitive information from audit events (e.g. for privacy or compliance reasons) without breaking the tamper-evidence guarantees of the log.

## 9. Verifiable Export

The ability to export audit events (or the full log) in a form that allows the recipient to independently verify their integrity.

## 10. Compliance Reporting

Support for generating reports over the audit log to support compliance and audit needs.
