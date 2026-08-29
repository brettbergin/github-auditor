"""Exception hierarchy for github-auditor."""


class AuditorError(Exception):
    """Base class for all github-auditor errors."""


class AuthError(AuditorError):
    """The GitHub token is missing, invalid, or lacks required scopes."""


class RateLimitError(AuditorError):
    """The GitHub API rate limit was exhausted and could not be waited out."""


class CloneError(AuditorError):
    """A repository could not be cloned or updated locally."""


class CacheError(AuditorError):
    """The local cache database is unusable (e.g. schema version mismatch)."""
