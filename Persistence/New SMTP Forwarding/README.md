# Mailbox SMTP Forwarding Set for a User

Hunts for mailbox-level SMTP forwarding configured in Exchange Online by a specific user. Use it during post-incident investigations to check whether an attacker set the compromised mailbox to forward mail to an address they control.

| | |
| --- | --- |
| **Query** | [KQL](./new_smtp_forwarding.kql) (Defender XDR / Sentinel) |
| **Type** | Hunting query (post-incident investigation) |
| **Category** | Persistence |
| **Data source** | Exchange Online audit events via Defender for Cloud Apps (`CloudAppEvents`) |
| **MITRE ATT&CK** | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) Email Collection: Email Forwarding Rule |
| **Author** | Robert Popeleski |

## Background

Setting `ForwardingSmtpAddress` on a mailbox sends a copy of every incoming message to another address, usually external. Unlike inbox rules, it doesn't appear in the user's rule list, and it keeps working after a password reset. Attackers use it to keep collecting mail from a compromised account and to watch for replies in business email compromise and invoice fraud.

## Query logic

1. Pull `Set-Mailbox` events from `CloudAppEvents` within the lookback window.
2. Keep events where the acting user (`RawEventData.UserId`) contains `targetUserId`.
3. Expand the command's parameters and keep events where `ForwardingSmtpAddress` was set to a non-empty value.
4. Return the formatted event time and the full raw audit record.

## Parameters

| Parameter | Placeholder | Description |
| --- | --- | --- |
| `targetUserId` | `<USER UPN>` | UPN of the compromised or suspected user. Matched with `contains`. |
| Lookback | `<LOOKBACK mm,d,M>` | Value inside `ago()`. How far back to search, such as `30m` or `7d`. |

## Output

| Column | Description |
| --- | --- |
| `DateOccurred` | Time of the change, formatted as `MM/dd/yyyy hh:mm AM/PM` |
| `RawEventData` | Full audit record, including all `Set-Mailbox` parameters |

## Reviewing results

Details are in `RawEventData`. Fields to check:

- **`ForwardingSmtpAddress`:** the destination. External domains, free email providers, and addresses resembling the user's own name are high priority.
- **`DeliverToMailboxAndForward`:** `True` keeps a copy in the mailbox, so the user doesn't notice missing mail. This is common in attacker-set forwarding.
- **`Identity`:** the mailbox that was changed. Confirm it matches the target user.
- **`ClientIP`:** compare against the IPs tied to the compromise and the user's known locations.
- **Timing:** forwarding set shortly after the initial compromise is high priority.

## False positives

Forwarding set by the user to a personal or secondary account, and forwarding configured for a departing employee or a shared role. Most organizations treat user-set external forwarding as a policy issue even when it isn't malicious, so confirm with the user and check it against policy.

## Known blind spots

- **Actor vs. mailbox owner:** `RawEventData.UserId` is the account that ran the command. Forwarding set on the target's mailbox by a different account (such as an admin or another compromised account) won't match. Check the `Identity` parameter to find the affected mailbox.
- **Other forwarding methods:** `ForwardingAddress` (forwarding to an internal recipient or mail contact), inbox rules, and transport rules are not covered. See the inbox rule query for rule-based forwarding.
- **Forwarding removal:** events that clear `ForwardingSmtpAddress` are excluded, so the query doesn't show when or whether forwarding was later removed.
- **Effectiveness:** outbound spam policies may block external auto-forwarding, so a configured address doesn't confirm mail was delivered. Check message trace.
- **UPN matching:** `contains` also matches longer UPNs that include the target (for example, `jsmith` matches `jsmith2`). An empty `targetUserId` matches every user.
- **Sort order:** results are not sorted. Sort by date when reviewing.
- **Time column:** the query uses `TimeGenerated`. If it errors in standalone Defender XDR Advanced Hunting, use `Timestamp`.
- **Lookback units:** KQL timespans support `m` (minutes), `h`, and `d`, but not months. Use days for long lookbacks, up to the 30-day Advanced Hunting retention limit.
- Requires the Microsoft 365 app connector in Defender for Cloud Apps.

## Triage

Confirm with the user whether they set the forwarding, and compare the destination and `ClientIP` against the compromise timeline. If it's unrecognized, remove the forwarding (`Set-Mailbox -ForwardingSmtpAddress $null`), use message trace to determine what was already forwarded, and block the destination address. Revoke sessions and reset the password if not already done, and review the account for related persistence: inbox rules, new MFA methods, and OAuth app consents.
