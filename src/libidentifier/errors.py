"""Structured exceptions used by LibIdentifier."""


class LibIdentifierError(Exception):
    """Base class for package errors."""


class InputError(LibIdentifierError):
    """The top-level input cannot be inspected safely."""


class ProfileError(LibIdentifierError):
    """The profile database is missing, incompatible, or corrupt."""


class ProfileBuildError(LibIdentifierError):
    """A trusted reference profile could not be built."""


class ParserError(LibIdentifierError):
    """A binary parser failed for a selected artifact."""

