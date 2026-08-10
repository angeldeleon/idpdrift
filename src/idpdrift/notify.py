"""Outbound notifications: Slack, generic webhook, and email.

Destinations are read from the environment, named in config but never stored
there, so a repository can carry a committed config without carrying a secret.
Every HTTP destination goes through the SSRF guard; SMTP verifies certificates.

Findings are addressed to the **security or identity team**, never to the account
holder. That is deliberate. "Your account has no second factor" sent to five
hundred people generates helpdesk load, gets filtered, and — for the findings
that matter here — tips off exactly the person whose account may already be under
someone else's control.

Every payload is bounded. A tenant with a thousand findings must not produce a
webhook request the receiver drops, because the scan that found the most would
then be the one that alerted least.
"""

from __future__ import annotations

import logging
import re
import smtplib
import ssl
from email.message import EmailMessage

from .config import NotifyConfig, NotifyEmailConfig
from .httpclient import HTTPError, safe_request
from .models import FindingKind, ScanReport, Severity
from .validation import ValidationError

log = logging.getLogger(__name__)

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Slack rejects a message with more than 50 blocks. Each finding costs two, on
# top of a header, a summary, a divider and a possible "and N more" footer, so 20
# findings (44 blocks) leaves room. notify.max_findings_per_message accepts up to
# 100, which without this cap produces a message Slack refuses outright.
_MAX_SLACK_FINDINGS = 20

_SEVERITY_EMOJI = {
    Severity.CRITICAL: ":rotating_light:",
    Severity.HIGH: ":large_orange_diamond:",
    Severity.MEDIUM: ":warning:",
    Severity.LOW: ":information_source:",
    Severity.INFO: ":white_circle:",
}


def notify(report: ScanReport, config: NotifyConfig, *, user_agent: str = "idpdrift") -> list[str]:
    """Deliver findings at or above the configured severity.

    Returns human-readable error strings. Delivery failures are reported but
    never raise: a scan that found a new Global Administrator and could not reach
    Slack has still done its job, and its exit code must reflect the finding
    rather than the delivery failure.
    """
    errors: list[str] = []

    relevant = [f for f in report.findings if f.severity >= config.min_severity]
    if not relevant:
        log.info("no findings at or above %s; skipping notifications", config.min_severity.value)
        return errors

    relevant.sort(key=lambda f: (-f.severity.rank, f.check, f.subject))

    if config.webhook_url():
        try:
            _post_generic(
                config.webhook_url() or "",
                report,
                relevant,
                limit=config.max_findings_per_message,
                user_agent=user_agent,
            )
        except (HTTPError, ValidationError) as exc:
            errors.append(f"webhook delivery failed: {exc}")
            log.error("webhook delivery failed: %s", exc)

    if config.slack_webhook_url():
        try:
            _post_slack(
                config.slack_webhook_url() or "",
                report,
                relevant,
                limit=config.max_findings_per_message,
                user_agent=user_agent,
            )
        except (HTTPError, ValidationError) as exc:
            errors.append(f"Slack delivery failed: {exc}")
            log.error("Slack delivery failed: %s", exc)

    if config.email.enabled:
        try:
            _send_email(config.email, report, relevant, limit=config.max_findings_per_message)
        except (OSError, smtplib.SMTPException, ssl.SSLError, ValidationError) as exc:
            errors.append(f"email delivery failed: {exc}")
            log.error("email delivery failed: %s", exc)

    return errors


# --------------------------------------------------------------------------


def _post_generic(url: str, report: ScanReport, findings: list, *, limit: int, user_agent: str) -> None:
    # Capped like every other destination. The severity counts and the total stay
    # whole, so a receiver can always tell it is looking at a subset and go to the
    # report for the rest.
    shown = findings[:limit]
    payload = {
        "tool": "idpdrift",
        "tool_version": report.tool_version,
        "tenant": report.tenant,
        "scanned_at": report.finished_at,
        "identities_seen": report.identities_seen,
        "affected_subjects": report.affected_subjects(),
        "counts_by_severity": report.counts_by_severity(),
        "counts_by_determination": report.counts_by_determination(),
        "indeterminate_facets": report.indeterminate_facets[:50],
        "findings": [f.to_dict() for f in shown],
        "findings_total": len(findings),
        "findings_truncated": len(findings) > len(shown),
    }
    response = safe_request("POST", url, json_body=payload, user_agent=user_agent)
    if response.status_code >= 400:
        raise HTTPError(f"webhook returned HTTP {response.status_code}")


def _post_slack(url: str, report: ScanReport, findings: list, *, limit: int, user_agent: str) -> None:
    counts = report.counts_by_severity()
    drift_count = sum(1 for f in findings if f.kind is FindingKind.DRIFT)

    header = (
        f"*idpdrift* — {len(findings)} finding(s) across "
        f"{report.affected_subjects()} of {report.identities_seen} identity/identities"
        + (f", *{drift_count} changed since last scan*" if drift_count else "")
    )
    summary = (
        f"critical: {counts['critical']} · high: {counts['high']} · "
        f"medium: {counts['medium']} · low: {counts['low']}"
    )

    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": summary}]},
        {"type": "divider"},
    ]

    shown = min(limit, _MAX_SLACK_FINDINGS)
    for finding in findings[:shown]:
        emoji = _SEVERITY_EMOJI[finding.severity]
        marker = " _(changed)_" if finding.kind is FindingKind.DRIFT else ""
        check = f" · `{_escape_code(finding.check)}`"
        # Two blocks, deliberately. The first is ours: the severity emoji, the
        # subject and the check name, all in positions we control.
        #
        # The subject goes in a code span rather than bold. It is a pseudonym
        # for a person, but for a workload it is the application's display name
        # — never pseudonymised, and chosen by whoever registered it. In an
        # mrkdwn field a name like `*RESOLVED*` or `~~ignore~~` formats itself
        # inside the alert header, and mrkdwn has no backslash escape to stop
        # it. Nothing formats inside a code span, and _escape_code replaces the
        # one character that could close it early.
        #
        # The second carries the title and detail, which interpolate a
        # directory-chosen display name, and it is plain_text with emoji
        # disabled. Slack applies no mrkdwn inside plain_text, so an application
        # name cannot bold itself, open a code span, or expand
        # `:white_check_mark:` into a reassuring green tick. Escaping alone could
        # not achieve that: Slack mrkdwn has no backslash escape, so the only
        # options are to mangle the name with lookalike characters or to choose a
        # context where the markup is not interpreted. This is the latter.
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} `{_escape_code(finding.subject)}`{check}{marker}",
                },
            }
        )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "emoji": False,
                    "text": f"{_plain(finding.title)}\n{_plain(_truncate(finding.detail, 350))}",
                },
            }
        )

    if len(findings) > shown:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"_…and {len(findings) - shown} more. See the full report._",
                    }
                ],
            }
        )

    response = safe_request(
        "POST",
        url,
        json_body={"text": f"idpdrift: {len(findings)} finding(s)", "blocks": blocks},
        user_agent=user_agent,
    )
    if response.status_code >= 400:
        raise HTTPError(f"Slack returned HTTP {response.status_code}")


def _send_email(config: NotifyEmailConfig, report: ScanReport, findings: list, *, limit: int) -> None:
    counts = report.counts_by_severity()
    subject = (
        f"[idpdrift] {len(findings)} finding(s) on {report.affected_subjects()} identity/identities"
        f" — {counts['critical']} critical, {counts['high']} high"
    )

    body_lines = [
        f"idpdrift scanned {report.identities_seen} identity/identities at {report.finished_at}.",
        f"{report.affected_subjects()} have findings at or above the notification threshold.",
        "",
        f"critical {counts['critical']} | high {counts['high']} | medium {counts['medium']} "
        f"| low {counts['low']} | info {counts['info']}",
        "",
    ]
    if report.indeterminate_facets:
        body_lines += [
            "Could not be determined: " + ", ".join(report.indeterminate_facets[:20]),
            "",
        ]
    for finding in findings[:limit]:
        marker = " (changed since last scan)" if finding.kind is FindingKind.DRIFT else ""
        body_lines += [
            f"{finding.severity.value.upper()}{marker} — {finding.subject} [{finding.check}]",
            f"  {finding.title}",
            f"  {_truncate(finding.detail, 400)}",
            "",
        ]
    if len(findings) > limit:
        body_lines.append(f"...and {len(findings) - limit} more. See the full report.")

    message = EmailMessage()
    # EmailMessage refuses embedded newlines in headers, and the addresses were
    # validated at config-parse time — belt and braces against header injection.
    message["Subject"] = _header_safe(subject)
    message["From"] = config.from_address
    message["To"] = ", ".join(config.to_addresses)
    message["Auto-Submitted"] = "auto-generated"
    message.set_content("\n".join(_header_safe(line, allow_empty=True) for line in body_lines))

    context = ssl.create_default_context()

    if config.smtp_port == 465 and not config.use_starttls:
        with smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=30, context=context) as smtp:
            _authenticate(smtp, config)
            smtp.send_message(message)
        return

    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=30) as smtp:
        smtp.ehlo()
        if config.use_starttls:
            smtp.starttls(context=context)
            smtp.ehlo()
        _authenticate(smtp, config)
        smtp.send_message(message)


def _authenticate(smtp: smtplib.SMTP, config: NotifyEmailConfig) -> None:
    username = config.username()
    password = config.password()
    if username and password:
        smtp.login(username, password)


def _escape(text: object) -> str:
    """Neutralise directory-supplied text before it reaches a Slack channel.

    Display names are attacker-chosen for an account or application an attacker
    created. Escaping mrkdwn entities is not enough on its own: a newline lets a
    crafted value forge an extra line in the alert — a fake ":white_circle: all
    clear", say — so control characters are collapsed first.
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    return collapsed.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _plain(text: object) -> str:
    """Prepare directory-supplied text for a Slack ``plain_text`` field.

    No mrkdwn is interpreted there, so nothing needs escaping for formatting —
    and entity-escaping would be wrong, printing a literal ``&lt;`` to the
    channel. Control characters still have to go, because a newline would let a
    crafted name forge an extra line inside the block.
    """
    return " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())


def _escape_code(text: object) -> str:
    """Neutralise a value rendered inside a Slack code span.

    :func:`_escape` alone is not sufficient: a backtick in the value closes the
    span early and lets the remainder render as mrkdwn.
    """
    return _escape(text).replace("`", "'")


def _header_safe(text: object, *, allow_empty: bool = False) -> str:
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    return collapsed if (collapsed or allow_empty) else "-"


def _truncate(text: object, limit: int) -> str:
    value = str(text)
    return value if len(value) <= limit else value[: limit - 1] + "…"
