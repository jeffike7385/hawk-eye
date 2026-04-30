import argparse
import getpass
import os
import sys
import tempfile
import time
import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from hawk_scan import __version__
from hawk_scan.config import load_config, load_fingerprints, merge_fingerprints
from hawk_scan.models import ScanResult, ScanReport
from hawk_scan.remote.transport import Credentials, negotiate_transport
from hawk_scan.scanner.engine import ScanEngine
from hawk_scan.scanner.orchestrator import ScanOrchestrator
from hawk_scan.report.generator import generate_html_report, generate_json_report

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hawk_scan",
        description="Remote endpoint PII and secrets scanner for Windows domain environments",
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--paths", nargs="+", help="Remote paths to scan")
    parser.add_argument("--exclude", nargs="+", default=[], help="Exclude patterns")
    parser.add_argument("--username", help="Domain\\username for authentication")
    parser.add_argument("--password", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--transport", choices=["winrm", "smb"], default=None)
    parser.add_argument("--report-format", choices=["html", "json"], default="html")
    parser.add_argument("--output", default=".", help="Output directory")
    parser.add_argument("--config", default=None, help="Path to config.yml")
    parser.add_argument("--custom-fingerprints", default=None, help="Path to custom fingerprints")
    parser.add_argument("--redact", action="store_true", help="Redact matched values")
    parser.add_argument("--max-file-size", type=int, default=50, help="Max file size in MB")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s v{__version__}")
    return parser


def main():
    import warnings
    warnings.filterwarnings("ignore", module="openpyxl")
    warnings.filterwarnings("ignore", module="PyPDF2")

    parser = build_parser()
    args = parser.parse_args()

    if args.username and not args.password:
        args.password = getpass.getpass(f"Password for {args.username}: ")

    config = load_config(args.config)
    if args.exclude:
        config["exclude_patterns"] = list(set(config.get("exclude_patterns", []) + args.exclude))

    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(__file__)))
    default_fp_path = os.path.join(base_dir, "fingerprints", "default.yml")

    default_fps = load_fingerprints(default_fp_path)
    custom_fp_path = args.custom_fingerprints or config.get("custom_fingerprints")
    custom_fps = load_fingerprints(custom_fp_path) if custom_fp_path else None
    fingerprints = merge_fingerprints(default_fps, custom_fps)

    redact = args.redact or config.get("report", {}).get("redact", False)
    engine = ScanEngine(fingerprints, redact=redact)

    if args.username:
        creds = Credentials(username=args.username, password=args.password)
    else:
        creds = Credentials.current_user()

    timeout = config.get("timeout_seconds", 30)

    console.print(f"[bold]Hawk Scan v{__version__}[/bold]")
    console.print(f"Target: [cyan]{args.target}[/cyan]")

    try:
        transport = negotiate_transport(args.target, creds, timeout, args.transport, debug=args.debug)
    except ConnectionError as e:
        console.print(f"[bold red]{e}[/bold red]")
        sys.exit(1)

    console.print(f"Transport: [green]{transport.name}[/green]")

    scan_paths = args.paths or config.get("default_paths", ["C:\\Users"])
    if not args.paths and len(scan_paths) == 1 and scan_paths[0] == "C:\\Users":
        try:
            volumes = transport.detect_volumes()
            for v in volumes:
                if v != "C:\\" and v not in scan_paths:
                    scan_paths.append(v)
        except Exception:
            pass

    max_file_mb = args.max_file_size or config.get("max_file_size_mb", 50)
    orchestrator = ScanOrchestrator(
        transport=transport, engine=engine, max_file_size_mb=max_file_mb, debug=args.debug,
    )

    start_time = time.time()
    start_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    exclude_patterns = config.get("exclude_patterns", [])

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        console=console, transient=True,
    ) as enum_progress:
        enum_task = enum_progress.add_task("Enumerating remote files...", total=None)

        def on_enum(count, filename):
            enum_progress.update(enum_task, description=f"Enumerating... {count} files found")

        file_list = orchestrator.enumerate(scan_paths, exclude_patterns, progress_callback=on_enum)
    console.print(f"Found [bold]{len(file_list)}[/bold] scannable files")

    temp_dir = tempfile.mkdtemp(prefix="hawk_scan_")
    try:
        with Progress(
            SpinnerColumn(), BarColumn(), TextColumn("{task.completed}/{task.total} files"),
            TextColumn("[progress.description]{task.description}"), console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(file_list))

            def on_progress(file_path):
                import ntpath
                name = ntpath.basename(file_path)
                if len(name) > 40:
                    name = name[:37] + "..."
                progress.update(task, advance=1, description=f"Scanning {name}")

            findings, skipped = orchestrator.scan(
                file_list=file_list,
                temp_dir=temp_dir, progress_callback=on_progress,
            )
    finally:
        try:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            console.print(f"[yellow]Warning: could not clean temp dir {temp_dir}: {e}[/yellow]")

    end_time = time.time()
    end_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = end_time - start_time

    scan_user = args.username or os.environ.get("USERNAME", os.environ.get("USER", "unknown"))

    result = ScanResult(
        target_host=args.target, transport_method=transport.name, scan_user=scan_user,
        start_time=start_ts, end_time=end_ts, duration_seconds=duration,
        total_files_scanned=len(findings) + len(skipped), total_files_skipped=len(skipped),
        findings=findings, skipped_files=skipped,
    )
    report = ScanReport(result=result)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_format = args.report_format or config.get("report", {}).get("format", "html")
    output_dir = args.output or config.get("report", {}).get("output_dir", ".")
    filename = f"hawk_scan_{args.target}_{timestamp}.{report_format}"
    output_path = os.path.join(output_dir, filename)

    if report_format == "html":
        generate_html_report(report, output_path)
    else:
        generate_json_report(report, output_path)

    console.print(f"\n[bold green]Scan complete.[/bold green]")
    console.print(f"  Files scanned: {result.total_files_scanned}")
    console.print(f"  Files skipped: {result.total_files_skipped}")
    console.print(f"  Findings: {len(findings)}")
    console.print(f"  Duration: {duration:.1f}s")
    console.print(f"  Report: {output_path}")


if __name__ == "__main__":
    main()
