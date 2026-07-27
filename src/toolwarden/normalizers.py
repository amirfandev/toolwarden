"""The shipped fact keys and their normalizers.

These are the only functions in the package that read raw model-controlled
arguments. Each one turns an argument into a typed fact or into
`Unavailable`, and never raises for expected bad input: a raise would still
fail closed under the engine's batch contract, but the audit reason would
read "raised TypeError" instead of a sentence written for a compliance
reviewer. Graceful failure is returned, not raised.

The domain extraction (`_email_domain`) and the keyword sets are carried
over from the measured prototype, which was measured correct against its
adversarial corpus. The SQL noise stripping is NOT the prototype's: the
prototype stripped string literals, then comments, in independent regex
passes, and that ordering is a proven fail-open (a quote inside a comment
opened a phantom literal that ate a write keyword, classifying
`SELECT 1 /*'*/ ; DELETE FROM users /*'*/` as a read). It is replaced by a
single left-to-right scan in `_strip_sql_noise`; the corpus that measured
the prototype had no case in this class, which is why the measurement
missed it. The interface also changed: each public name below is a
registered `Normalizer` whose result mapping the engine holds to the batch
contract, so "could not compute" is a value the gate turns into a deny,
never a silent empty.

Two distinct failure shapes, deliberately kept apart:

  In-band "cannot prove it": `_classify_sql("DR/**/OP TABLE x")` succeeds
  and returns `SqlClass.UNKNOWN`. The input was a string; the honest answer
  is "unprovable", and a policy judges that answer (and denies it in
  production).

  Unavailable: `classify_sql` over `{"query": {"$gt": ""}}` has nothing to
  classify. The fact does not exist, the policy body never runs, the engine
  denies UNPARSEABLE on its behalf.

Both paths end in a deny for a production write policy, by different
mechanisms, and neither depends on a policy author checking anything.
"""

from __future__ import annotations

import enum
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from toolwarden.facts import FactKey, Unavailable
from toolwarden.normalize import normalizer
from toolwarden.types import ToolCall

# ---------------------------------------------------------------------------
# SQL classification
# ---------------------------------------------------------------------------


class SqlClass(enum.Enum):
    """What a SQL string provably is. UNKNOWN is an answer, not a failure:
    it means "not provably a read", which write-restricting policies treat
    exactly like WRITE."""

    READ = "read"
    WRITE = "write"
    UNKNOWN = "unknown"


SQL_CLASS: FactKey[SqlClass] = FactKey("sql_class")

_SQL_WORD = re.compile(r"[A-Za-z_]+")

# The characters a provably-read statement is allowed to contain once its
# string literals, quoted identifiers, and comments have been blanked out.
# Letters, digits, whitespace, and the punctuation of ordinary read syntax
# (operators, separators, parentheses). Every character NOT in this set is a
# construct the lexer does not model: a dialect quote or comment introducer
# (`$` for PostgreSQL dollar-quoting, `[`/`]` for T-SQL identifiers, a
# backslash, a stray control byte) that could reinterpret a `'` or `"` the
# scanner already resolved. Their presence in the stripped code forces
# UNKNOWN, because the scanner cannot then prove its own tokenization matches
# the engine's. See `_strip_sql_noise`.
_SAFE_SQL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " \t\r\n\f\v"
    "_.,;:()*/%+-=<>!~&|^?@"
)

_WRITE_KEYWORDS = frozenset(
    {"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER",
     "CREATE", "GRANT", "REVOKE", "MERGE", "REPLACE"}
)
_READ_STARTERS = frozenset({"SELECT", "WITH", "EXPLAIN", "SHOW", "VALUES"})


@dataclass(frozen=True)
class _StripResult:
    """The blanked query, plus the two signals that block a read certification.

    `unterminated` is set when a string literal, quoted identifier, or block
    comment never closes: the lexer swallows everything after the opener, and
    whatever it hid, a write keyword included, becomes invisible to the keyword
    scan. A valid single statement does not leave one open, so this signals
    malformed SQL or a poisoning attempt.

    `unmodeled` is set when the stripped code (everything left after literals,
    identifiers, and comments are blanked) contains a character outside
    `_SAFE_SQL_CHARS`. That character is a construct this lexer does not model,
    e.g. a PostgreSQL dollar sign or a T-SQL bracket, and such a construct can
    quote a `'` or `"` the scanner instead resolved as a string boundary. When
    that happens the scanner cannot prove its tokenization matches the engine's,
    so the result is not a provable read.

    Either signal, with no visible write keyword, forces UNKNOWN, which
    write-restricting policies deny.
    """

    text: str
    unterminated: bool
    unmodeled: bool


def _strip_sql_noise(query: str) -> _StripResult:
    """Blank out string literals, quoted identifiers, and comments in one pass.

    One pass, not layered regex substitutions, because the layers interact:
    a SQL engine opens whichever construct appears first and everything
    inside it is inert until it closes. Stripping strings across the whole
    text before comments (as the prototype did) let a quote INSIDE a
    comment open a phantom literal that swallowed a later write keyword, so
    `SELECT 1 /*'*/ ; DELETE FROM users /*'*/` classified as a read.
    Stripping comments first has the mirror-image hole for `--` or `/*`
    inside a real literal. Consuming each construct where it actually opens
    has neither.

    Quote-delimited spans are `'...'`, `"..."`, and MySQL backtick
    identifiers `` `...` ``, each closing on a matching delimiter with a
    doubled delimiter as an escape. Backticks are modeled, not passed
    through, because otherwise a `'` inside a backtick identifier opens a
    phantom literal; with two of them the phantom pairs up and closes
    cleanly, swallowing any write between the identifiers (input
    `` SELECT 1 AS `a'b`; DELETE FROM users; SELECT 2 AS `c'd` ``). Modeled,
    the identifier's contents are inert and the `DELETE` stays visible.

    Line comments are `--`; block comments are `/* */`. `#` is NOT treated as
    a comment: it is a line comment only in MySQL and the integer bitwise-XOR
    operator in PostgreSQL, so blanking to end of line would hide a real write
    after a `#` operator (`SELECT 5 # 3; DELETE FROM users`). Passed through as
    an ordinary character, a write after a `#` stays visible (WRITE) and a
    stray quote after a `#` runs a literal off the end (`unterminated`); both
    deny.

    An unterminated literal, identifier, or block comment runs to end of input,
    which is what a SQL lexer does, and is reported so the classifier refuses
    to call the result a read. So is any leftover character outside the modeled
    read grammar (`unmodeled`); the two together close the family of
    "unrecognized construct reinterprets a quote" holes, paired phantoms
    included.
    """
    out: list[str] = []
    unterminated = False
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
        if ch in ("'", '"', "`"):
            # Literal or quoted identifier; a doubled delimiter is an escape.
            i += 1
            closed = False
            while i < n:
                end = query.find(ch, i)
                if end == -1:
                    i = n
                    break
                if end + 1 < n and query[end + 1] == ch:
                    i = end + 2
                    continue
                i = end + 1
                closed = True
                break
            if not closed:
                unterminated = True
            out.append(" ")
        elif ch == "-" and query.startswith("--", i):
            end = query.find("\n", i)
            i = n if end == -1 else end
            out.append(" ")
        elif ch == "/" and query.startswith("/*!", i):
            # MySQL executable comment: the server runs its contents while
            # other engines treat it as inert. Blanking it would hide a write
            # (`/*! DELETE FROM t */`), so its interior is scanned as code. Skip
            # the `/*!` marker and any version gate digits (`/*!50000`), then
            # let the main loop tokenize what follows; the trailing `*/` becomes
            # two ordinary safe characters. A visible write inside now denies.
            i += 3
            while i < n and query[i].isdigit():
                i += 1
        elif ch == "/" and query.startswith("/*", i):
            end = query.find("*/", i + 2)
            if end == -1:
                i = n
                unterminated = True
            else:
                i = end + 2
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    text = "".join(out)
    unmodeled = any(c not in _SAFE_SQL_CHARS for c in text)
    return _StripResult(text, unterminated, unmodeled)


def _classify_sql(query: str) -> SqlClass:
    """Classify a SQL string as read, write, or unknown.

    String literals, quoted identifiers, and comments are blanked before
    keyword inspection, so 'update' inside a literal does not misclassify a
    read, and a keyword split by an inline comment (DR/**/OP) does not
    reassemble into a write: it tokenizes to unknown, which the calling policy
    treats as deny.

    A construct that ran off the end unterminated, or a leftover character
    outside the modeled read grammar, forces UNKNOWN: in either case the lexer
    cannot prove what it saw was not a hidden write.
    """
    stripped = _strip_sql_noise(query)
    tokens = [t.upper() for t in _SQL_WORD.findall(stripped.text)]
    # A visible write keyword is definitive and outranks everything, including
    # an unterminated or unmodeled construct later in the string: a write is a
    # write.
    if any(t in _WRITE_KEYWORDS for t in tokens):
        return SqlClass.WRITE
    # No visible write. An unterminated construct ran off the end, or an
    # unmodeled character means a construct outside the recognized grammar
    # could have reinterpreted a quote; either way the result is not a
    # provable read.
    if stripped.unterminated or stripped.unmodeled:
        return SqlClass.UNKNOWN
    if not tokens:
        return SqlClass.UNKNOWN
    if tokens[0] in _READ_STARTERS:
        return SqlClass.READ
    return SqlClass.UNKNOWN


@normalizer("classify_sql", tools=("db_exec",), provides=(SQL_CLASS,))
def classify_sql(call: ToolCall) -> Mapping[FactKey[Any], object]:
    """SQL_CLASS for db_exec, or Unavailable when there is nothing to classify.

    A non-string query (a mongo-style operator object, a number, None,
    nothing at all) is not "unknown SQL": it is not SQL, and pretending
    otherwise would launder a structural problem into an in-band value.
    """
    query = call.args.get("query")
    if not isinstance(query, str):
        return {SQL_CLASS: Unavailable("sql_class", "query is missing or not a string")}
    return {SQL_CLASS: _classify_sql(query)}


# ---------------------------------------------------------------------------
# Email recipient domains
# ---------------------------------------------------------------------------

RECIPIENT_DOMAINS: FactKey[frozenset[str]] = FactKey("recipient_domains")


def _email_domain(address: str) -> str | None:
    """The registrable domain of one address, or None if it cannot be trusted.

    The address must contain exactly one '@'; the domain is what follows it,
    compared whole. An address with zero or several '@' signs is refused
    outright (None), not split at a final '@', because "which @ is the
    separator" is exactly the ambiguity an attacker exploits. A suffix check
    on the raw string is the classic hole: 'evil@sub.ourcompany.com.
    attacker.com' contains 'ourcompany.com' but its domain is attacker.com's.
    """
    address = address.strip()
    if address.count("@") != 1:
        return None
    local, _, domain = address.partition("@")
    domain = domain.lower()
    if not local or not domain:
        return None
    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        return None
    return domain


@normalizer("recipient_domains", tools=("send_email",), provides=(RECIPIENT_DOMAINS,))
def recipient_domains(call: ToolCall) -> Mapping[FactKey[Any], object]:
    """Every recipient's domain, or Unavailable if any one recipient is
    untrustworthy.

    One unparseable recipient poisons the whole fact, because partial trust
    is no trust: a policy allowing "all domains internal" must never judge a
    list from which the hostile entry was quietly dropped. Reasons never
    echo the address; a hostile or mistyped address is exactly the value
    that must not land in the audit record or the transcript.
    """
    to = call.args.get("to")
    if not isinstance(to, list):
        return {
            RECIPIENT_DOMAINS: Unavailable(
                "recipient_domains", "recipient field 'to' is missing or not a list"
            )
        }
    if not to:
        return {
            RECIPIENT_DOMAINS: Unavailable("recipient_domains", "recipient list 'to' is empty")
        }
    domains: set[str] = set()
    for addr in to:
        if not isinstance(addr, str):
            return {
                RECIPIENT_DOMAINS: Unavailable(
                    "recipient_domains", "a recipient entry is not a string"
                )
            }
        domain = _email_domain(addr)
        if domain is None:
            return {
                RECIPIENT_DOMAINS: Unavailable(
                    "recipient_domains",
                    "a recipient address does not resolve to a single trustworthy domain",
                )
            }
        domains.add(domain)
    return {RECIPIENT_DOMAINS: frozenset(domains)}


# ---------------------------------------------------------------------------
# USD amounts
# ---------------------------------------------------------------------------

AMOUNT_USD: FactKey[float] = FactKey("amount_usd")


@normalizer("usd_amount", tools=("issue_refund", "charge"), provides=(AMOUNT_USD,))
def usd_amount(call: ToolCall) -> Mapping[FactKey[Any], object]:
    """The amount in USD as a float, or Unavailable for anything untrusted.

    bool is rejected before the numeric check because a Python bool IS an
    int: `True` would otherwise become 1.00 USD and sail under any cap.
    Non-finite values are rejected too: NaN compares False against every
    cap, which would turn `amount_usd=float("nan")` into an allow under a
    "deny if amount > cap" policy. That comparison trap is exactly the kind
    of input this normalizer exists to keep out of policy bodies.
    """
    amount = call.args.get("amount_usd")
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        return {AMOUNT_USD: Unavailable("amount_usd", "amount_usd is missing or not a number")}
    try:
        value = float(amount)
    except OverflowError:
        return {
            AMOUNT_USD: Unavailable("amount_usd", "amount_usd is too large to represent")
        }
    if not math.isfinite(value):
        return {AMOUNT_USD: Unavailable("amount_usd", "amount_usd is not a finite number")}
    return {AMOUNT_USD: value}


# ---------------------------------------------------------------------------
# PHI tagging and fax destination
# ---------------------------------------------------------------------------

PHI_FIELDS: FactKey[tuple[str, ...]] = FactKey("phi_field_names")


@normalizer("phi_fields", tools=("send_email", "send_fax"), provides=(PHI_FIELDS,))
def phi_fields(call: ToolCall) -> Mapping[FactKey[Any], object]:
    """The declared PHI field names, () when genuinely untagged, Unavailable
    when the tag is present but malformed.

    The distinction is the fix for the prototype's PHI-blind-allow bug: the
    old code mapped `phi_fields="patient_ssn"` (a string, not a list) to the
    same empty tuple as "no PHI", so a malformed tag silently allowed the
    send. Here, absent means absent and computes to (); present-but-broken
    means the caller claimed something about PHI that cannot be read, and
    that is Unavailable, which the gate turns into a deny.
    """
    if "phi_fields" not in call.args:
        return {PHI_FIELDS: ()}
    tagged = call.args["phi_fields"]
    if not isinstance(tagged, list) or not all(isinstance(f, str) for f in tagged):
        return {
            PHI_FIELDS: Unavailable(
                "phi_field_names", "phi_fields is present but is not a list of strings"
            )
        }
    return {PHI_FIELDS: tuple(tagged)}


FAX_NUMBER: FactKey[str] = FactKey("fax_number")


@normalizer("fax_number", tools=("send_fax",), provides=(FAX_NUMBER,))
def fax_number(call: ToolCall) -> Mapping[FactKey[Any], object]:
    """The fax destination as given, or Unavailable when it is not a usable
    string. No format normalization in v0.1: allow-list policies compare
    exact strings, and a lenient rewrite here would widen what an allow-list
    entry matches without the policy author ever seeing it happen.
    """
    number = call.args.get("fax_number")
    if not isinstance(number, str) or not number:
        return {
            FAX_NUMBER: Unavailable("fax_number", "fax_number is missing, empty, or not a string")
        }
    return {FAX_NUMBER: number}


__all__ = (
    "AMOUNT_USD",
    "FAX_NUMBER",
    "PHI_FIELDS",
    "RECIPIENT_DOMAINS",
    "SQL_CLASS",
    "SqlClass",
    "classify_sql",
    "fax_number",
    "phi_fields",
    "recipient_domains",
    "usd_amount",
)
