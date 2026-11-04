# MFA Method Changes with Probable Source IP

Hunts for MFA method changes on a user's account in Microsoft Entra ID, and attaches the IP address of the user's most recent successful sign-in before each change as the probable source. Use it during post-incident investigations to check whether an attacker registered their own MFA method to keep access after a compromise.

| | |
| --- | --- |
| **Query** | [KQL](./mfa_method_changes.kql) (Sentinel / Defender XDR unified portal) |
| **Type** | Hunting query (post-incident investigation) |
| **Category** | Persistence |
| **Data source** | Entra ID audit logs (`AuditLogs`), interactive and non-interactive sign-in logs (`SigninLogs`, `AADNonInteractiveUserSignInLogs`) |
| **MITRE ATT&CK** | [T1098.005](https://attack.mitre.org/techniques/T1098/005/) Account Manipulation: Device Registration · [T1556.006](https://attack.mitre.org/techniques/T1556/006/) Modify Authentication Process: Multi-Factor Authentication |
| **Author** | Robert Popeleski |

## Background

Once an attacker has a user's password and a valid session, registering their own authenticator app or phone number is one of the most effective ways to keep access. The new method survives a password reset, lets the attacker pass future MFA prompts, and can be used to reset the password again through self-service password reset. Finding and removing attacker-registered methods is a required step in remediating a compromised account.

## Query logic

1. Find audit events where a `StrongAuthentication*` property was modified on the user object, or where the operation name contains "registered security info".
2. Expand the target resources and keep those whose UPN contains `targetUserId`.
3. Find successful interactive and non-interactive sign-ins (`ResultType` 0) from the last X days.
4. Join the changes to the sign-ins on user, keeping only sign-ins at or before each change.
5. For each change, keep the most recent of those sign-ins and report its IP as the probable source.

## Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `targetUserId` | `<USER UPN>` | UPN of the compromised or suspected user. Matched with `contains`. |
| Audit lookback | `<LOOKBACK mm,d,M>` | How far back to search for MFA changes. |
| Sign-in lookback | `<LOOKBACK mm,d,M>` | How far back to search for matching sign-ins. |

## Output

| Column | Description |
| --- | --- |
| `DateOccurred` | Time of the MFA change, formatted as `MM/dd/yyyy hh:mm AM/PM` |
| `TargetUser` | UPN of the account whose MFA methods changed |
| `ProbableIPAddress` | IP of the user's most recent successful sign-in at or before the change |
| `ModifiedProperties` | Raw modified properties from the audit record, including method details |

## Reviewing results

- **`ProbableIPAddress`:** compare against the IPs tied to the compromise and the user's known locations.
- **`ModifiedProperties`:** shows the method details, such as a new phone number or authenticator device name. Compare against the user's real devices.
- **Timing:** changes shortly after the initial compromise are high priority.

## False positives

Users setting up a new phone, replacing a lost device, re-registering after a helpdesk MFA reset, and new employees completing first-time registration all generate the same events. These typically come from the user's usual IP and device. Confirm with the user or helpdesk when unclear.

## Known blind spots

- **Probable IP is a heuristic:** there is no limit on how long before the change the matched sign-in occurred, so the IP may come from an unrelated session hours or days earlier, or from background non-interactive sign-ins on the user's own device.
- **Changes without a matching sign-in are dropped:** the inner join removes any change with no successful sign-in for the target user in the last X days, and any change older than the sign-in lookback.
- **Admin- or app-initiated changes:** when an admin or an application changes the methods, the target user's sign-in IP doesn't reflect who made the change. The query doesn't return the initiator.
- **Operation coverage:** deleted or changed security info is only caught if the record includes a `StrongAuthentication*` property, since the operation filter matches "registered security info" only.
- **UPN matching:** `contains` also matches longer UPNs that include the target (for example, `jsmith` matches `jsmith2`). An empty `targetUserId` matches every user.
- **Sort order:** results are sorted by `DateOccurred`, a text string, so they are not in true chronological order. Sort by date when reviewing.
- **Retention:** results are limited to what the Sentinel workspace retains for `AuditLogs` and sign-in logs.
- **Platform:** these tables require a Sentinel workspace. Standalone Defender XDR Advanced Hunting without Sentinel doesn't have them.
- **Performance:** `AADNonInteractiveUserSignInLogs` is high volume, and all users' sign-ins are joined before filtering. Long lookbacks may be slow.

## Triage

Confirm with the user whether they registered or changed each method, and compare the probable IP against the compromise timeline and the user's known locations. Check the audit record directly for who initiated the change. For any unrecognized method, remove it, revoke all sessions, and reset the password, then require the user to re-register MFA from a trusted device. Also review the account for related persistence: inbox rules, mail forwarding, OAuth app consents, and new device registrations.
