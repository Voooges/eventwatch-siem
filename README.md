# EventWatch

A Python SIEM prototype for Windows security log analysis. Import events, apply five explainable detection rules, inspect supporting evidence, and export alerts. Runs locally on macOS, Windows, or Linux using Python 3.10+ with **no third-party dependencies**.

## Run on your Mac / PyCharm

1. Extract the ZIP and open the EventWatch folder in PyCharm.
2. Select a Python 3.10+ project interpreter.
3. Run `app.py`, or enter the following in the PyCharm terminal:

```sh
python3 app.py
```

4. Open http://127.0.0.1:8501 in your browser.
5. Click **Load synthetic demo**. Expect **14 events, 5 alerts, 3 high-severity alerts, 1 host**.
6. Click an alert to investigate its evidence. Filter alerts and export a JSON report.

You do not need Kali Linux. The Mac analyzes Windows logs as data files. A Windows VM can be added later to generate real events. The demo uses fictional users and documentation IP addresses; it does not perform attacks.

## Detection rules

| Rule | Condition | Severity | Possible benign cause |
|---|---|---|---|
| EW001 | 5 failed logins (4625) within 5 minutes | Medium | Stale credentials |
| EW002 | Successful login (4624) after 5 failures within 5 minutes | High | Correct password after mistakes |
| EW003 | Account created (4720) | Medium | Approved onboarding |
| EW004 | Group addition (4732) to Administrators SID S-1-5-32-544 | High | Approved access change |
| EW005 | Security log cleared (1102) | High | Authorized maintenance |

Correlation matches host, domain, user, and source IP. Missing user/IP prevents login correlation. EW001 emits at the threshold for each active sequence; success resets the sequence. `engine.detect` accepts threshold and window arguments. Alerts require investigation and do not prove compromise.

## Import formats

Accepts JSON arrays and Windows event XML (single Event or Events root). Each request allows up to 10 MiB and 20,000 events. Binary EVTX and CSV are not supported. Export selected events as XML in Windows Event Viewer, or on your own Windows lab use elevated PowerShell:

```powershell
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4720,4732,1102} -MaxEvents 500
$xml = '<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join "`n") + '</Events>'
[IO.File]::WriteAllText("$PWD\security-events.xml", $xml)
```

Relevant Windows audit policies must be enabled for events to be generated. Transfer the XML to your Mac and import it. Keep real security logs out of public repositories.

Example JSON:

```json
[{"timestamp":"2026-10-19T14:10:00Z","event_id":4625,"host":"LAB-PC-01","user":"alex","domain":"LAB","source_ip":"192.0.2.25","record_id":"100"}]
```

Required: timezone-aware timestamp, numeric event_id, nonempty host. Optional string fields: user, domain, source_ip, record_id, actor, member, group_sid. Preserve record_id to distinguish otherwise identical events. XML maps Windows EventData fields and the 1102 UserData actor to this schema.

## Architecture

JSON/XML → normalize and validate → deduplicated SQLite storage → event-time rules → browser dashboard and JSON reports.

- `engine.py`: parser, normalization, persistence, detection.
- `app.py`: local HTTP API, bound to 127.0.0.1 only.
- `dashboard.html`: dashboard with no external scripts.
- `samples/demo.json`: reproducible synthetic scenario.
- `tests/test_engine.py`: detection and ingestion tests.

SHA-256 fingerprints deduplicate normalized events. Every import is validated before writes. Detection recomputes across stored events in timestamp order, supporting out-of-order imports. The UI displays imported values as text. Host/Origin checks reject cross-origin browser requests.

## Tests

From the project folder:

```sh
python3 -m unittest discover -s tests -v
```

## Storage and limitations

Data persists in `data/events.db`. Stop the server and delete this database to reset. For a different dataset or port:

```sh
python3 app.py --port 8502 --db data/lab.db
```

This is a single-user educational batch analyzer. There is no live collection, authentication, alert status management, tamper-resistant storage, or multi-tenant support. Keep the built-in HTTP server local. All stored events are loaded into memory: keep datasets small. Correlation requiring source IP misses local-only logins. Input provider identities are not verified. Missing audit evidence cannot be reconstructed.

## Publish to GitHub

Create an empty repository named `eventwatch-siem`, then publish this folder using PyCharm's Git integration or GitHub's upload interface. Include source, tests, and synthetic samples. The `.gitignore` excludes databases, environments, and IDE settings. Add your own dashboard screenshot and document a detection you extend so you can explain your work in interviews.

Suggested description: **Python SIEM prototype with Windows event ingestion, correlation rules, SQLite storage, and an investigation dashboard.**

## Next milestones

- Alert status and investigation notes.
- Versioned rule configuration.
- Windows log collector with authenticated ingestion.
- Indexed incremental analysis and performance benchmarks.

## References

- [Microsoft Windows event reference](https://learn.microsoft.com/azure/sentinel/windows-security-event-id-reference)
- [Microsoft event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft events to monitor](https://github.com/MicrosoftDocs/windowsserverdocs/blob/main/WindowsServerDocs/identity/ad-ds/plan/Appendix-L--Events-to-Monitor.md)

MIT License — see LICENSE.

## Suggested lab: Mac + Windows VM + Surface

Run this dashboard on your Mac. Use your Windows VM as the first log source: make a few manual incorrect login attempts with a dedicated test account, then sign in correctly. Avoid account lockouts; check your lab policy first. Export the resulting Security events as XML and import them on the Mac. Event timestamps and source IP availability determine whether login correlation triggers; use the synthetic demo for a guaranteed five-rule walkthrough.

Later export a small log sample from your Surface and import it too. The Computer field preserves the source host, and correlation does not mix failures across different hosts. No agent or network connection between the devices is required in this version. Use the VM for experimental account/group changes rather than changing your everyday Surface setup.
