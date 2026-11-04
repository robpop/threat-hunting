# Search Endpoint Activity by File SHA256

Searches every Defender for Endpoint table that records a SHA256 hash and returns one timeline of everything tied to a single file: where it was written, where it ran, what it launched, what it connected to, and which processes loaded it. Use it when you have a known-bad hash from an alert, a sandbox report, or threat intelligence and need to find every device it touched and how it got there.

| | |
| --- | --- |
| **Query** | [KQL](./search_file_sha256.kql) (Defender XDR Advanced Hunting) |
| **Type** | Hunting query (IOC sweep / post-incident investigation) |
| **Category** | Investigation |
| **Data source** | Defender for Endpoint device events (`DeviceEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceImageLoadEvents`) |
| **MITRE ATT&CK** | Technique-agnostic. Commonly used to scope [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File and [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer |
| **Author** | Robert Popeleski |

## Background

A file hash is one of the most reliable indicators you can get, but searching one table at a time leaves gaps. A file can be downloaded (`DeviceFileEvents`), executed (`DeviceProcessEvents`), make network connections (`DeviceNetworkEvents`), be loaded as a DLL by another process (`DeviceImageLoadEvents`), or show up in AV detections and other miscellaneous events (`DeviceEvents`). Searching all of them at once, in time order, shows the full lifecycle of the file across the environment: first arrival, spread, execution, and follow-on activity.

## Query logic

1. **Set the hash and lookback:** define the target SHA256 and how far back to search.
2. **Search each table:** match the hash against the columns each table offers.
   - `DeviceEvents`, `DeviceFileEvents`, `DeviceProcessEvents`: the file itself (`SHA256`) or the process that performed the action (`InitiatingProcessSHA256`).
   - `DeviceNetworkEvents`: the process that made the connection (`InitiatingProcessSHA256`).
   - `DeviceImageLoadEvents`: the loaded image (`SHA256`).
3. Combine the results with `union`.
4. Project a common set of columns covering file, process, account, download origin, and network details.
5. Sort oldest first so the earliest event, likely when the file was introduced, is at the top.

## Parameters

| Parameter | Placeholder / Default | Description |
| --- | --- | --- |
| `TargetHash` | `<SHA256_HASH_HERE>` | SHA256 of the file to search for. Matched exactly and case-sensitively. Use lowercase, which is how Defender stores hashes. |
| `Lookback` | `30d` | How far back to search. Set once and applied to every table. Accepts `m`, `h`, or `d`. |

## Output

| Column | Description |
| --- | --- |
| `Timestamp` | Time of the event |
| `DeviceName` | Device the event occurred on |
| `ActionType` | What happened, such as `FileCreated`, `ProcessCreated`, `ConnectionSuccess`, `ImageLoaded`, or an AV detection type |
| `FileName` | Name of the file involved in the event |
| `FolderPath` | Full path of the file |
| `ProcessCommandLine` | Command line of the created process (process events) |
| `InitiatingProcessFileName` | Process that performed the action |
| `InitiatingProcessCommandLine` | Command line of the initiating process |
| `InitiatingProcessAccountName` | Account the initiating process ran as |
| `FileOriginUrl` | URL the file was downloaded from, when recorded |
| `FileOriginReferrerUrl` | Page that linked to the download, when recorded |
| `RemoteUrl` | Destination URL for network events |
| `RemoteIP` | Destination IP for network events |
| `RemotePort` | Destination port for network events |

Columns are empty for tables that don't record them. For example, network columns are only populated for `DeviceNetworkEvents` and some `DeviceEvents`.

## Reviewing results

- **First seen:** the top row is the earliest sighting. Check `FileOriginUrl`, `FileOriginReferrerUrl`, and `InitiatingProcessFileName` to see how the file arrived: a browser download, an email client, an archive tool, a remote copy over SMB, or a script.
- **Scope:** count distinct `DeviceName` and `InitiatingProcessAccountName` values to see how many devices and users are affected.
- **Execution:** `DeviceProcessEvents` rows where the hash matches `SHA256` mean the file was run. Rows where it matches `InitiatingProcessSHA256` show what the file did once running, such as child processes and the command lines used.
- **Network activity:** `DeviceNetworkEvents` rows show where the file connected after it ran. These are candidate C2 or staging destinations to block and to pivot on.
- **Image loads:** `ImageLoaded` rows mean another process loaded the file as a DLL. Check the loading process for sideloading or a hijacked legitimate application.
- **Lateral spread:** the same hash appearing on new devices over time, especially written by `System` or remote management tools, suggests it is being pushed across the network.
- **Pivot:** use any `RemoteUrl`, `RemoteIP`, or `FileOriginUrl` values to search for other devices that contacted the same infrastructure, which may reveal variants with different hashes.

## False positives

Not an alert. Results are as accurate as the hash. Confirm the hash is actually malicious before acting, since a hash taken from a widely used legitimate file (a common DLL or installer) will return large volumes of benign activity.

## Known blind spots

- **Hash coverage:** Defender does not compute a SHA256 for every event. Very large files, some files on network shares, and some file events may have an empty `SHA256`, so the file can be present without matching.
- **Case sensitivity:** `==` is case-sensitive. An uppercase hash will return no results. Convert the hash to lowercase, or change the comparisons to `=~`.
- **Tables not searched:** `DeviceRegistryEvents` (registry changes made by the file), `EmailAttachmentInfo` (the file arriving as an email attachment), and `DeviceFileCertificateInfo` (signer information) are not included. Search these separately if the file may have arrived by email or modified the registry.
- **Partial matching per table:** `DeviceNetworkEvents` is only matched on the initiating process, and `DeviceImageLoadEvents` only on the loaded image, not on the process that loaded it.
- **Unmanaged devices:** devices without Defender for Endpoint, including personal and most mobile devices, are not covered.
- **Modified files:** any change to the file, including repacking or recompiling, produces a new hash. A clean result does not mean related malware is absent.
- **Retention:** Advanced Hunting keeps 30 days of data. A file introduced before that window will appear to start later than it did, so the first row may not be the true initial access.
- **Performance:** `DeviceNetworkEvents` and `DeviceImageLoadEvents` are high volume. Long lookbacks may be slow or hit result limits.

## Triage

Confirm the file is malicious and identify the earliest sighting to determine how it was introduced. List every device and account that wrote, ran, or loaded it, and check each device for execution rather than just presence on disk. Block the hash through Defender indicators (block and remediate), and block any URLs, domains, or IPs found in the results. Isolate devices where the file executed and collect an investigation package. If the file came from a phishing email or download link, find other recipients and block the source. Review affected devices for persistence, such as scheduled tasks, services, Run keys, and new local accounts, and reset credentials for any account the file ran under if credential theft is suspected.
