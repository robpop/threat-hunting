# User URL Activity Across Email, Teams, and Endpoints

Builds a single timeline of URLs a user clicked or connected to, combining Safe Links clicks from email and Teams with URL activity from the user's Defender for Endpoint devices. Use it during post-incident investigations to find the phishing link that led to a compromise, confirm whether the user clicked it, and see what happened on the device afterward.

| | |
| --- | --- |
| **Query** | [KQL](./user_url_activity.kql) (Defender XDR Advanced Hunting) |
| **Type** | Hunting query (post-incident investigation) |
| **Category** | Investigation |
| **Data source** | Defender for Office 365 Safe Links clicks (`UrlClickEvents`), Defender for Endpoint network and device events (`DeviceNetworkEvents`, `DeviceEvents`) |
| **MITRE ATT&CK** | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Phishing: Spearphishing Link · [T1204.001](https://attack.mitre.org/techniques/T1204/001/) User Execution: Malicious Link |
| **Author** | Robert Popeleski |

## Background

Most account compromises start with a link: a credential phishing page, an adversary-in-the-middle login proxy, or a malicious download. The evidence is split across products. Safe Links records clicks in email and Teams, while Defender for Endpoint records what the browser and other processes on the device connected to. Combining them in one timeline shows the click, the pages that followed, and any unusual processes reaching out afterward.

## Query logic

1. **Safe Links clicks:** pull `UrlClickEvents` for the target user within the lookback window, labeled "Email or Teams (Safe Links)".
2. **Endpoint network activity:** pull `DeviceNetworkEvents` with a URL, where the initiating account matches the user's UPN or the part of the UPN before `@`. The source is labeled with the process that made the connection.
3. **Endpoint URL actions:** pull `DeviceEvents` for browsers launched to open a URL and SmartScreen URL warnings, matched to the user the same way. The URL comes from `RemoteUrl` or, if empty, from `AdditionalFields`.
4. Combine the three sources with a common set of columns.
5. Exclude failed network connections and sort newest first.

## Parameters

| Parameter | Placeholder | Description |
| --- | --- | --- |
| `targetUser` | `<USER UPN>` | UPN of the compromised or suspected user. Matched exactly (case-insensitive). The part before `@` is also matched against endpoint account names. |
| Lookback | `<LOOKBACK m,h,d>` | Value inside `ago()`. Appears three times, once per source. Set all three to the same value, such as `30m` or `7d`. |

## Output

| Column | Description |
| --- | --- |
| `Timestamp` | Time of the click or connection |
| `User` | UPN of the user. May be empty for endpoint events matched by account name only. |
| `Source` | Where the event came from: Safe Links, endpoint network (with process name), or endpoint action (with action type) |
| `Url` | URL clicked or connected to |
| `Status` | Outcome, such as `ClickAllowed`, `ClickBlocked`, `ConnectionSuccess`, or the endpoint action type |
| `DeviceName` | Device the activity occurred on. `N/A` for Safe Links clicks. |
| `RemoteIP` | Client IP for Safe Links clicks, destination IP for network events, empty for endpoint actions |

## Reviewing results

- **Phishing URL:** find the link from the reported or suspected phishing message, and check whether it was clicked and whether the click was allowed or blocked.
- **What followed the click:** look at endpoint activity in the minutes after. Unfamiliar login pages, lookalike Microsoft domains, URL shorteners, and file-sharing sites are high priority.
- **SmartScreen warnings:** a warning followed by continued activity to the same site may mean the user clicked through.
- **Process in `Source`:** connections from processes such as `powershell.exe`, `mshta.exe`, `rundll32.exe`, or script hosts suggest something was executed, not just browsed.
- **Timing:** compare click times against the first activity from attacker IPs (see the user activity by IP query). A sign-in from an unfamiliar IP minutes after a click suggests the user entered credentials on a phishing page.
- **Pivot:** search for the same URL across other users to find other recipients who clicked.

## False positives

Not an alert, but endpoint network activity is noisy. Background traffic from browsers, OneDrive, Teams, Office, and update services running under the user's account will make up most rows. Filter by time window or by `Source` to focus on browsing and unusual processes.

## Known blind spots

- **Safe Links coverage:** only links rewritten or protected by Safe Links appear in `UrlClickEvents`. Links in messages that bypassed Safe Links, and links opened outside protected apps, are not recorded there.
- **Unmanaged devices:** activity on personal or mobile devices without Defender for Endpoint only appears if it was a Safe Links click.
- **Account name matching:** matching the part of the UPN before `@` can miss users whose account name differs from their UPN prefix, and can match other accounts with the same name, such as local accounts.
- **URL availability:** network events without a `RemoteUrl` are excluded. Some connections only record an IP.
- **Endpoint actions:** browser launch and SmartScreen events are Windows-specific.
- **Missing tables:** `union isfuzzy=true` skips any source that isn't available (for example, without Defender for Office 365 Plan 2), without an error. Results may silently be from fewer than three sources.
- **Only failed connections are excluded:** attempted, accepted, and other network action types remain in the results.
- **Lookback units:** KQL timespans support `m` (minutes), `h`, and `d`, but not months. Use days for long lookbacks, up to the 30-day Advanced Hunting retention limit.
- **Performance:** `DeviceNetworkEvents` is high volume. Long lookbacks may be slow or hit result limits.

## Triage

Identify the phishing URL and when the user clicked it. Determine whether credentials were entered (sign-ins from new IPs shortly after the click) and whether anything was downloaded or executed (file and process events on the device around the same time). Find other users who received or clicked the same URL, block it through the Tenant Allow/Block List or Defender indicators, and isolate the device if execution is suspected. If credentials were exposed, revoke sessions, reset the password, and review the account for persistence: inbox rules, mail forwarding, new MFA methods, OAuth app consents, and guest sharing.
