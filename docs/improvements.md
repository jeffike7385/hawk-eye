# Hawk Scan — Planned Improvements

## Performance

### Parallel file scanning
Swap the sequential `for` loop in `orchestrator.scan()` for a `ThreadPoolExecutor` (4-8 workers). Retrieval is network-bound, so concurrent retrieve+scan would cut total scan time significantly. Need thread-safe findings/skipped lists and progress callback.

### SMB session reconnection
Long scans can hit SMB session timeouts. Add reconnection logic in `SmbTransport` if the session drops mid-scan — detect the error, re-register, and retry the current file.

## Usability

### Skip reason summary in console output
After scan completes, print a grouped breakdown of skip reasons instead of just a count:
```
Files skipped: 3500
  Retrieve failed: 3400
  Timed out: 50
  File too large: 30
  Read error: 20
```

### Estimated time remaining
Add ETA to the progress bar based on average time per file so far.

### Exit codes for scripting
- 0 = clean scan, no findings
- 1 = findings detected
- 2 = scan error (connection failed, etc.)

## Reporting

### Skip reason breakdown in HTML report
Group the skip list by reason with counts instead of listing every file individually. Keep the full list expandable for detail.

### CSV export
Add `--report-format csv` for feeding results into Excel, SIEM, or other tools.
