from datetime import datetime, timezone

from fastapi import HTTPException, status


def require_utc(value: datetime | None, *, field_name: str) -> datetime | None:
    """Reject timezone-naive datetimes rather than guessing their offset.

    Events are stored with server-generated UTC timestamps, so a
    timezone-naive `from`/`to` value is ambiguous - we don't know what
    timezone the caller meant. Values are normalized to UTC so the
    comparison against stored (UTC) timestamps is unambiguous regardless of
    which offset the caller used.

    Shared by every endpoint that accepts a from/to time-range filter
    (GET /audit/events, GET /audit/compliance/account-access), so the same
    validation rule can't drift between them.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"'{field_name}' must include timezone information (e.g. a 'Z' or '+00:00' offset)",
        )
    return value.astimezone(timezone.utc)


def validate_range(start_time: datetime | None, end_time: datetime | None) -> None:
    if start_time is not None and end_time is not None and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="'from' must not be later than 'to'",
        )
