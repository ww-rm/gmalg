"""GM Exceptions."""

__all__ = [
    "GMError",
    "CheckFailedError",
    "DataOverflowError",
    "IncorrectLengthError",
    "InfinitePointError",
    "InvalidArgumentError",
    "InvalidPCError",
    "PointNotOnCurveError",
    "RequireArgumentError",
    "UnknownError",
]


class GMError(Exception):
    """Base class of all errors in GM algorithms."""


class CheckFailedError(GMError):
    """Check failed."""


class DataOverflowError(GMError):
    """Data over maximum length limit."""

    def __init__(self, name: str, maxlen: str) -> None:
        """Over maximum length limit."""

        self.name = name
        self.maxlen = maxlen

    def __str__(self) -> str:
        return f"{self.name} more than {self.maxlen}."


class IncorrectLengthError(GMError):
    """Incorrect data length given."""

    def __init__(self, name: str, expected: str, given: str) -> None:
        """Incorrect data length given."""

        self.name = name
        self.expected = expected
        self.given = given

    def __str__(self) -> str:
        return f"{self.expected} expected for {self.name}, {self.given} given."


class InfinitePointError(GMError):
    """Encountered a point at infinity."""


class InvalidArgumentError(GMError):
    """Invalid arguments."""


class InvalidPCError(GMError):
    """Invalid PC byte."""

    def __init__(self, pc: int) -> None:
        self.pc = pc

    def __str__(self) -> str:
        return f"Invalid PC byte 0x{self.pc:x}."


class PointNotOnCurveError(GMError):
    """Point not on elliptic curve."""

    def __init__(self, P) -> None:
        """Point not on elliptic curve."""

        self.P = P

    def __str__(self) -> str:
        return f"Point{self.P} not on curve."


class RequireArgumentError(GMError):
    """Missing some required arguments."""

    def __init__(self, name: str, *args: str) -> None:
        """Missing some required arguments."""

        self.name = name
        self.args = args

    def __str__(self) -> str:
        return f"{self.name} requires {', '.join(self.args)}."


class UnknownError(GMError):
    """Unknown errors."""
