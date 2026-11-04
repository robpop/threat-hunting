# Inbox Rule Creation or Modification for a User

Hunts for inbox rules created or modified on a specific user's mailbox in Exchange Online. Use it during post-incident investigations to check whether an attacker left rules behind to hide, delete, or forward the victim's mail after an account compromise.

| | |
| --- | --- |
| **Query** | [KQL](./new_inbox_rules.kql) (Defender XDR Advanced Hunting) |
| **Type** | Hunting query (post-incident investigation) |
| **Category** | Persistence |
| **Data source** | Exchange Online audit events via Defender for Cloud Apps (`CloudAppEvents`) |
| **MITRE ATT&CK** | [T1564.008](https://attack.mitre.org/techniques/T1564/008/) Hide Artifacts: Email Hiding Rules · [T1114.003](https://attack.mitre.org/techniques/T1114/003/) Email Collection: Email Forwarding Rule |
| **Author** | Robert Popeleski |

## Background

After compromising a mailbox, attackers often create inbox rules to stay hidden and keep access to the conversation. Common goals are hiding security alerts and replies from the real user, deleting messages that would reveal the compromise, and forwarding mail to an external address. These rules survive a password reset, so they need to be found and removed as part of remediation.

## Query logic

1. Pull `New-InboxRule` and `Set-InboxRule` events from `CloudAppEvents` within the lookback window.
2. Filter to events where the acting user (`RawEventData.UserId`) matches the target UPN (case-insensitive exact match).
3. Return the event time, a formatted date string, and the full raw audit record, newest first.

## Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `targetUserId` | `user@contoso.com` | UPN of the compromised or suspected user |
| `lookback` | `7d` | How far back to search. Set this to cover the full suspected compromise window, up to the 30-day Advanced Hunting retention limit. |

## Reviewing results

Rule details are in `RawEventData.Parameters`. Fields that most often indicate malicious intent:

- **Forwarding:** `ForwardTo`, `RedirectTo`, or `ForwardAsAttachmentTo` pointing to an external address
- **Hiding:** `DeleteMessage`, `MarkAsRead`, or `MoveToFolder` targeting rarely checked folders such as RSS Feeds, RSS Subscriptions, Conversation History, or Archive
- **Keyword filters:** `SubjectContainsWords` or `SubjectOrBodyContainsWords` with terms like invoice, payment, wire, password, security, or phishing
- **Rule names:** very short or meaningless names such as `.`, `..`, or a single character
- **Source:** `ClientIP` in the raw record that doesn't match the user's known locations, or matches the IP from the initial compromise

## False positives

Users legitimately create rules to sort newsletters, move notifications into folders, or forward mail to a delegate. Rules built through Outlook on the web from the user's normal IP, with descriptive names and internal destinations, are usually benign. Confirm anything unclear with the user.

## Known blind spots

- **Outlook desktop rules:** rules created in the Outlook desktop client are usually logged under a different operation (`UpdateInboxRules`) and are not caught by this query.
- **Actor vs. mailbox owner:** `RawEventData.UserId` is the account that ran the command. Rules created on the target's mailbox by a different account (such as an admin or a delegate) won't match. Check the `Identity` or `Mailbox` parameter if delegated access is suspected.
- **Other forwarding methods:** mailbox-level forwarding (`Set-Mailbox` with `ForwardingSmtpAddress`), transport rules, and rule deletions (`Remove-InboxRule`) are out of scope.
- **Rules created before the lookback window** and rules created through Graph API or EWS that may log under different operations.
- **Sentinel:** in Log Analytics, replace `Timestamp` with `TimeGenerated`.
- Requires the Microsoft 365 app connector in Defender for Cloud Apps.

## Triage

Compare each rule against the compromise timeline and the attacker's known IPs. For any rule the user doesn't recognize, check whether mail was already forwarded or deleted (message trace or `EmailEvents`), then remove the rule with `Remove-InboxRule` or through Outlook on the web. Also review the account for related persistence: mailbox forwarding, new MFA methods, OAuth app consents, and active sessions. Revoke sessions and reset the password if not already done.
