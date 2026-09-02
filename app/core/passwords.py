from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

# Argon2id (this library's default) is OWASP's current recommendation for
# password hashing - a memory-hard function that's deliberately expensive to
# brute-force, unlike a plain fast hash (SHA-256, MD5, ...). Default cost
# parameters are used deliberately rather than hand-tuned: they're chosen by
# the library maintainers to be reasonable for an interactive login on
# ordinary hardware, and re-tuning them isn't something this prototype needs
# to get right.
_hasher = PasswordHasher()

# A hash of an unguessable, unused value - not a real user's credential -
# verified against on every login attempt for a username that doesn't exist
# in the configured user store (see app/core/security.py:authenticate_user).
# Its only purpose is to make an unknown-username attempt take roughly the
# same time as a wrong-password attempt for a real user, so a timing
# difference can't be used to enumerate valid usernames.
_DUMMY_HASH = _hasher.hash("not-a-real-password-used-only-for-timing")


def hash_password(password: str) -> str:
    """Hash a plaintext password for storage. Used to generate the
    password_hash values that go into AUTH_USERS (see .env.example) - never
    called at request time, since configured users' hashes are fixed
    config, not runtime input.
    """
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Check a submitted plaintext password against a stored hash. Returns
    False for a wrong password and also for a malformed/corrupt stored
    hash (InvalidHash) - either way, authentication should simply fail,
    not raise.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHash, ValueError):
        return False


def verify_unknown_user_password(password: str) -> None:
    """Burn the same amount of time verify_password() would take for a real
    user, without a real hash to check against - see _DUMMY_HASH above.
    """
    verify_password(password, _DUMMY_HASH)
