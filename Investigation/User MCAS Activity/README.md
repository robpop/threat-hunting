# User Cloud Activity Summarized by IP Address

Summarizes all of a user's cloud app activity by source IP address, showing when each IP was first and last seen, what it did, and which apps and objects it touched. Use it during post-incident investigations to separate the attacker's IPs from the user's own and to scope what the attacker did.

| | |
| --- | --- |
| **Query** | [KQL](./user_mcas_activity.kql) (Defender XDR / Sentinel) |
| **Type** | Hunting query (post-incident investigation) |
| **Category** | Investigation |
| **Data source** | Microsoft 365 and connected cloud app audit events via Defender for Cloud Apps (`CloudAppEvents`) |
| **MITRE ATT&CK** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts |
| **Author** | Robert Popeleski |

## Background

Once an account is confirmed compromised, the first questions are which IPs belong to the attacker and what they did from them. Grouping every action by IP makes unfamiliar ISPs and locations stand out next to the user's normal home, office, and mobile connections. The attacker IPs found here can then be used to scope activity in other queries and across other accounts.

## Query logic

1. Pull all `CloudAppEvents` within the lookback window.
2. Keep events where the acting user (`RawEventData.UserId`) contains `targetUserId`.
3. Group by IP address, country, city, and ISP.
4. For each group, return the first and last time seen (shifted 5 hours to EST), the number of actions, and the distinct actions, apps, and objects.
5. Sort by IP address, descending.

## Parameters

| Parameter | Placeholder | Description |
| --- | --- | --- |
| `targetUserId` | `<USER UPN>` | UPN of the compromised or suspected user. Matched with `contains`. |
| Lookback | `<LOOKBACK m,h,d>` | Value inside `ago()`. How far back to search, such as `30m` or `7d`. |

## Output

| Column | Description |
| --- | --- |
| `IPAddress`, `CountryCode`, `City`, `ISP` | Source IP and its geolocation and provider |
| `FirstSeen_EST` | First activity from this IP, formatted as `hh:mm:ss AM/PM MM/dd` |
| `LastSeen_EST` | Last activity from this IP, in the same format |
| `ActionCount` | Number of events from this IP |
| `Actions` | Distinct activity types (`ActionType`) |
| `Apps` | Distinct applications |
| `Objects` | Distinct objects acted on, such as files, mailboxes, or settings |

## Reviewing results

- **ISP and location:** hosting providers, VPN services, and countries the user doesn't work from are high priority. Mobile carriers and the user's home ISP are usually legitimate.
- **Actions:** look for sensitive activity from unfamiliar IPs, such as mail access, inbox rule creation, mailbox setting changes, file downloads, and sharing.
- **First and last seen:** compare against the compromise timeline. An unfamiliar IP whose first activity matches the suspected compromise time is likely the attacker's.
- **Pivot:** run the other queries in this repo for the attacker IPs, and search for the same IPs across other accounts to find additional compromised users.

## False positives

This is a summary rather than an alert, but some legitimate patterns can look suspicious: travel, mobile carriers that rotate IPs, IPv6 privacy addresses that produce many distinct IPs, and corporate VPNs or security proxies that egress from hosting providers. Compare against the user's known locations and confirm unclear IPs with the user.

## Known blind spots

- **Fixed EST offset:** times are shifted by a fixed 5 hours. During daylight saving time (EDT), they are one hour off.
- **No year:** the time format omits the year, which can be ambiguous for lookbacks that span a year boundary.
- **Sort order:** results are sorted by IP address as text, not by time. Sort by first seen when building a timeline.
- **Sign-ins not included:** Entra ID sign-ins are not in `CloudAppEvents`, so IPs that only signed in without other activity won't appear. Check sign-in logs separately.
- **Actor only:** `RawEventData.UserId` is the account that performed the action. Events without a `UserId` in the raw record, and actions taken on the user's resources by another account, are not included.
- **Split rows:** the same IP can appear on more than one row if its geolocation or ISP changed during the lookback.
- **UPN matching:** `contains` also matches longer UPNs that include the target (for example, `jsmith` matches `jsmith2`). An empty `targetUserId` matches every user.
- **Lookback units:** KQL timespans support `m` (minutes), `h`, and `d`, but not months. Use days for long lookbacks, up to the 30-day Advanced Hunting retention limit.
- **Time column:** the query uses `TimeGenerated`. If it errors in standalone Defender XDR Advanced Hunting, use `Timestamp`.
- Requires the relevant app connectors in Defender for Cloud Apps.

## Triage

Mark each IP as the user's or the attacker's, using ISP, location, timing, and confirmation from the user. For attacker IPs, review every action and object listed to scope what was accessed or changed, then check the account for persistence (inbox rules, mail forwarding, new MFA methods, OAuth app consents, and guest sharing). Search for the attacker IPs across the tenant to find other affected accounts, and consider blocking them through Conditional Access.
