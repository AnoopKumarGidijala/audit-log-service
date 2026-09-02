from fastapi import Depends, HTTPException, status

from app.core.roles import Role
from app.core.security import CurrentUser, get_current_user


def require_roles(*allowed_roles: Role):
    """FastAPI dependency factory: authorization, kept separate from
    authentication (app.core.security.get_current_user establishes *who*
    is calling; this decides *whether* that identity's role may perform
    the operation the endpoint declares it for - see
    docs/authorization-design.md).

    Each route states its own required roles at the point of declaration
    (e.g. Depends(require_roles(Role.ADMIN))), so a sensitive endpoint's
    permission requirement is explicit and visible there rather than
    inferred from shared, generic auth wiring.
    """

    def _require_roles(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.value}' is not permitted to perform this operation.",
            )
        return user

    return _require_roles
