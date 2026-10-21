"""Operator-owned prompt evidence references, never persisted protected values."""

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from urllib.parse import urlsplit, urlunsplit
from yarl import URL

from src.core.model_selection import canonical_model_overrides
from src.core.redaction import contains_literal
from src.core.scope import ScopeValidationError
from src.utils.request_builder import SUPPORTED_PROVIDERS, resolve_api_key


PIN_FIELD = "_evidence_profile_pins"
MAX_FILE_BYTES = 65536
MAX_PROFILES = 100
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ENV = re.compile(r"SCAN_EVIDENCE_[A-Z][A-Z0-9_]{0,111}\Z")
_MARKER = re.compile(r"[A-Za-z0-9_.~-]{16,128}\Z")
_FIELDS = frozenset({"organization_id", "endpoint", "provider", "model",
                     "evidence_context_id", "system_prompt_canary_env"})
_ERROR = "Evidence profile is unavailable or does not match the selected asset; review server configuration"


class EvidenceProfileError(ScopeValidationError):
    """Static public failure with no protected value or server path."""

    def __init__(self):
        super().__init__(_ERROR)


def _text(value, maximum=256):
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and value == value.strip() and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def canonical_endpoint(value):
    """Normalize authority only; preserve exact path bytes and reject query input."""
    if (not _text(value, 4096) or not value.isascii()
            or any(char in value for char in ("?", "#", "\\", "%"))):
        raise EvidenceProfileError()
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
        if (parsed.scheme not in {"http", "https"} or not host or parsed.username is not None
                or parsed.password is not None or "%" in parsed.netloc
                or not host.isascii() or (port is not None and not 1 <= port <= 65535)):
            raise EvidenceProfileError()
        if (any(segment in {".", ".."} for segment in parsed.path.split("/"))
                or URL(value).raw_path != (parsed.path or "/")):
            raise EvidenceProfileError()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                raise EvidenceProfileError() from None
            host = host.lower()
        if ":" in host:
            host = "[" + host + "]"
        return urlunsplit((parsed.scheme, f"{host}:{port or (443 if parsed.scheme == 'https' else 80)}",
                           parsed.path or "/", "", ""))
    except (ValueError, TypeError):
        raise EvidenceProfileError() from None


def validate_references(value):
    if not isinstance(value, dict) or len(value) > MAX_PROFILES:
        raise EvidenceProfileError()
    for asset_id, profile_id in value.items():
        if not _text(asset_id) or not isinstance(profile_id, str) or not _ID.fullmatch(profile_id):
            raise EvidenceProfileError()
    return dict(value)


@dataclass(frozen=True)
class _Profile:
    organization_id: str
    endpoint: str
    provider: str
    model: str
    evidence_context_id: str
    system_prompt_canary_env: str = field(repr=False)
    revision: str


class EvidenceProfiles:
    """Immutable public bindings; protected values are read only for validation/use."""

    def __init__(self, profiles=None):
        self._profiles = MappingProxyType(dict(profiles or {}))

    @classmethod
    def from_document(cls, document):
        try:
            if (not isinstance(document, dict) or set(document) != {"schema_version", "profiles"}
                    or document["schema_version"] != "1.0" or not isinstance(document["profiles"], dict)
                    or len(document["profiles"]) > MAX_PROFILES):
                raise EvidenceProfileError()
            profiles = {}
            for identifier, entry in document["profiles"].items():
                if (not isinstance(identifier, str) or not _ID.fullmatch(identifier)
                        or not isinstance(entry, dict) or set(entry) != _FIELDS
                        or not _text(entry["organization_id"], 64)
                        or entry["provider"] not in SUPPORTED_PROVIDERS
                        or not _text(entry["model"])
                        or not _text(entry["evidence_context_id"], 128)
                        or any(char in entry["evidence_context_id"] for char in "[]")
                        or not isinstance(entry["system_prompt_canary_env"], str)
                        or entry["system_prompt_canary_env"] == "SCAN_EVIDENCE_PROFILES_FILE"
                        or not _ENV.fullmatch(entry["system_prompt_canary_env"])):
                    raise EvidenceProfileError()
                public = {**entry, "endpoint": canonical_endpoint(entry["endpoint"])}
                revision = hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                profiles[identifier] = _Profile(**public, revision=revision)
            registry = cls(profiles)
            for identifier in profiles:
                registry._marker(identifier)
            return registry
        except (KeyError, TypeError, ValueError, UnicodeError):
            raise EvidenceProfileError() from None

    def _marker(self, identifier):
        profile = self._profiles.get(identifier)
        if profile is None:
            raise EvidenceProfileError()
        marker = os.environ.get(profile.system_prompt_canary_env)
        if not isinstance(marker, str) or not _MARKER.fullmatch(marker):
            raise EvidenceProfileError()
        if marker in _ERROR or marker in "Scan execution failed" or marker in "Scan worker failed":
            raise EvidenceProfileError()
        # A public binding must never accidentally carry the protected marker.
        for candidate in self._profiles.values():
            if any(marker in value for value in (candidate.organization_id, candidate.endpoint,
                   candidate.provider, candidate.model, candidate.evidence_context_id,
                   candidate.system_prompt_canary_env, candidate.revision)):
                raise EvidenceProfileError()
        if any(marker in value for value in self._profiles):
            raise EvidenceProfileError()
        if any(marker in value for value in _FIELDS | {PIN_FIELD, "evidence_profiles", "evidence_profile_revisions"}):
            raise EvidenceProfileError()
        return marker

    def validate_public_definition(self, definition, references):
        """Do not persist selected markers in operator-supplied public labels/IDs."""
        for identifier in set(validate_references(references).values()):
            if contains_literal(definition, self._marker(identifier)):
                raise EvidenceProfileError()

    @staticmethod
    def _validate_public_inventory(agents, marker):
        if contains_literal(agents, marker):
            raise EvidenceProfileError()
        for agent in agents:
            endpoint = agent.get("endpoint")
            if endpoint and marker in str(URL(endpoint)):
                raise EvidenceProfileError()
            key = resolve_api_key(agent)
            if key and marker in key:
                raise EvidenceProfileError()

    def references(self, agents, references, tenant, aliases=None, *, pins=None):
        """Validate public selections, returning canonical refs and nonsecret pins."""
        try:
            references = canonical_model_overrides(agents, validate_references(references), aliases)
            by_id = {agent["id"]: agent for agent in agents}
            current = {}
            for asset_id, identifier in references.items():
                profile = self._profiles.get(identifier)
                agent = by_id[asset_id]
                if (profile is None or profile.organization_id != tenant
                        or canonical_endpoint(agent.get("endpoint")) != profile.endpoint
                        or agent.get("provider") != profile.provider or agent.get("model") != profile.model):
                    raise EvidenceProfileError()
                marker = self._marker(identifier)
                self._validate_public_inventory(agents, marker)
                current[asset_id] = profile.revision
            if pins is not None and pins != current:
                raise EvidenceProfileError()
            return references, current
        except (KeyError, TypeError, ValueError):
            raise EvidenceProfileError() from None

    def apply(self, agents, references, tenant, pins):
        references, _ = self.references(agents, references, tenant, pins=pins)
        selected = deepcopy(agents)
        for agent in selected:
            if agent["id"] in references:
                identifier = references[agent["id"]]
                profile = self._profiles[identifier]
                marker = self._marker(identifier)
                self._validate_public_inventory(agents, marker)
                agent["system_prompt_canary"] = marker
                agent["evidence_context_id"] = profile.evidence_context_id
        return selected

    def token(self, references, pins, tenant):
        """Bounded memory-only schedule revalidation, no filesystem or network."""
        current = {}
        for asset_id, identifier in validate_references(references).items():
            profile = self._profiles.get(identifier)
            if profile is None or profile.organization_id != tenant:
                raise EvidenceProfileError()
            self._marker(identifier)
            current[asset_id] = profile.revision
        if pins != current:
            raise EvidenceProfileError()
        return current


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceProfileError()
        result[key] = value
    return result


def load_evidence_profiles(path):
    """Read a private owned regular file once, rejecting unsafe types before read."""
    if not path:
        return EvidenceProfiles()
    descriptor = None
    try:
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise EvidenceProfileError()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) not in {0o400, 0o600} or before.st_size > MAX_FILE_BYTES):
            raise EvidenceProfileError()
        content = bytearray()
        while len(content) <= MAX_FILE_BYTES:
            part = os.read(descriptor, min(8192, MAX_FILE_BYTES + 1 - len(content)))
            if not part:
                break
            content.extend(part)
        after = os.fstat(descriptor)
        if (len(content) > MAX_FILE_BYTES or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise EvidenceProfileError()
        document = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(EvidenceProfileError()))
        return EvidenceProfiles.from_document(document)
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        raise EvidenceProfileError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
