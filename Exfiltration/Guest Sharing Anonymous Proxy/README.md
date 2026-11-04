# Guest Sharing Link from an Anonymous Proxy

Hunts for SharePoint and OneDrive sharing links that grant access to a guest user, created by a user connecting through an anonymous proxy. Use it during post-incident investigations to check whether an attacker used a compromised account to share files with an external account they control.

| | |
| --- | --- |
| **Query** | [KQL](./guest_sharing_anonymous_proxy.kql) (Defender XDR / Sentinel) |
| **Type** | Hunting query (post-incident investigation) |
| **Category** | Exfiltration |
| **Data source** | SharePoint Online and OneDrive audit events via Defender for Cloud Apps (`CloudAppEvents`) |
| **MITRE ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service · [T1213.002](https://attack.mitre.org/techniques/T1213/002/) Data from Information Repositories: SharePoint · [T1090](https://attack.mitre.org/techniques/T1090/) Proxy |
| **Author** | Robert Popeleski |

## Background

After compromising an account, attackers often connect through anonymizing proxies or VPN services to hide their location. Sharing files or folders with an external guest account gives them ongoing access to the data that doesn't depend on the compromised account, and it survives a password reset or session revocation. A guest sharing link created from an anonymous proxy is a strong signal that someone other than the user is moving data out.

## Query logic

1. Pull `AddedToSecureLink` events (a user or guest added to a "specific people" sharing link) from `CloudAppEvents` within the lookback window.
2. Keep events where the source IP is tagged as an anonymous proxy.
3. Keep events where the recipient is a guest.
4. Extract the guest recipient, the user who shared, and the site URL from the raw record.
5. Keep events where the sharing user's UPN contains `targetUserId` (case-insensitive).
6. Return the event details, identity, device, network, and raw audit record.

## Parameters

| Parameter | Placeholder | Description |
| --- | --- | --- |
| `targetUserId` | `<USER UPN>` | UPN of the compromised or suspected user. Matched with `contains`. |
| Lookback | `<LOOKBACK m,h,d>` | Value inside `ago()`. How far back to search, such as `30m` or `7d`. |

## Output

| Column(s) | Description |
| --- | --- |
| `Timestamp` | Time of the event |
| `TargetGuestUser` | The guest who was granted access through the link |
| `TargetUserId` | UPN of the user who shared (the actor, despite the column name) |
| `TargetSiteUrl` | SharePoint or OneDrive site containing the shared item |
| `IPAddress`, `ISP`, `IPTags`, `IsAnonymousProxy` | Network details of the session that created the link |
| `AccountObjectId`, `AccountId`, `AccountDisplayName` | Identity of the sharing user |
| `ApplicationId`, `Application` | Application that recorded the event |
| `DeviceType`, `OSPlatform`, `UserAgent` | Device and client details |
| `UncommonForUser`, `LastSeenForUser` | Defender for Cloud Apps indicators of whether attributes of this event are unusual for the user |
| `ActivityObjects`, `RawEventData` | Objects involved and the full audit record, including the shared item |
| `ReportId` | Unique event identifier |

## Reviewing results

- **`TargetGuestUser`:** free email providers, unfamiliar domains, and addresses resembling the user's own name are high priority.
- **Shared item:** check `RawEventData` (such as `ObjectId` and `SourceFileName`) and `ActivityObjects` to see what was shared. Financial, HR, and credential-related files are high priority.
- **`IPAddress` and `ISP`:** compare against the IPs tied to the compromise. Other activity from the same IP is likely attacker activity.
- **`UncommonForUser`:** values here indicate attributes Defender for Cloud Apps considers unusual for this user, such as the ISP or location.
- **Volume:** many links created in a short period, or to the same guest across sites, suggest bulk exfiltration.

## False positives

Users on consumer VPNs or privacy services that are tagged as anonymous proxies, sharing files with legitimate partners or vendors. Check the guest against known business contacts and confirm with the user.

## Known blind spots

- **Other sharing methods:** anonymous ("anyone") links, organization-wide links, and direct sharing invitations log under different operations and are not covered.
- **Proxy tagging:** attackers using residential proxies, hosting providers, or IPs not tagged as anonymous proxies are not detected.
- **Guest recipients only:** sharing with recipients not typed as `Guest` is excluded.
- **Column naming:** `TargetUserId` holds the user who shared, not the recipient. `targetUserId` filters on the sharer.
- **UPN matching:** `contains` also matches longer UPNs that include the target (for example, `jsmith` matches `jsmith2`). An empty `targetUserId` matches every user, which hunts tenant-wide.
- **Sort order:** results are not sorted. Sort by `Timestamp` when reviewing.
- **Time columns:** the query filters on `TimeGenerated` and returns `Timestamp`. If `TimeGenerated` errors in standalone Defender XDR Advanced Hunting, use `Timestamp` in the filter.
- **Lookback units:** KQL timespans support `m` (minutes), `h`, and `d`, but not months. Use days for long lookbacks, up to the 30-day Advanced Hunting retention limit.
- Requires the Microsoft 365 app connector in Defender for Cloud Apps.

## Triage

Confirm with the user whether they shared the item with the guest, and compare the IP and guest against the compromise timeline. If the sharing is unrecognized, remove the guest's access to the link and the item, remove the guest account from the tenant if it was invited, and check for file access or downloads by the guest. Review other sharing activity from the same user and IP, revoke sessions, and reset the password if not already done. Also review the account for related persistence: inbox rules, mail forwarding, new MFA methods, and OAuth app consents.
