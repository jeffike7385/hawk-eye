import os
import json
import ntpath
from collections import defaultdict
from dataclasses import asdict
from markupsafe import Markup, escape as markup_escape
from jinja2 import Environment, FileSystemLoader, select_autoescape
from hawk_scan import __version__
from hawk_scan.models import ScanReport

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SEVERITY_WEIGHT = {"high": 10, "medium": 3, "low": 1}


def _sorted_findings(report: ScanReport):
    return sorted(
        report.result.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path),
    )


def _directory_priorities(report: ScanReport) -> list[dict]:
    dir_stats = defaultdict(lambda: {"high": 0, "medium": 0, "low": 0, "total": 0, "files": set()})
    for f in report.result.findings:
        parent = ntpath.dirname(f.file_path)
        if not parent:
            parent = f.file_path
        dir_stats[parent]["total"] += 1
        dir_stats[parent][f.severity] += 1
        dir_stats[parent]["files"].add(f.file_path)

    priorities = []
    for directory, stats in dir_stats.items():
        score = (stats["high"] * SEVERITY_WEIGHT["high"]
                 + stats["medium"] * SEVERITY_WEIGHT["medium"]
                 + stats["low"] * SEVERITY_WEIGHT["low"])
        priorities.append({
            "directory": directory,
            "score": score,
            "high": stats["high"],
            "medium": stats["medium"],
            "low": stats["low"],
            "total": stats["total"],
            "file_count": len(stats["files"]),
        })
    return sorted(priorities, key=lambda p: -p["score"])


def generate_html_report(report: ScanReport, output_path: str) -> None:
    template_dir = os.path.join(os.path.dirname(__file__))
    def _dir_link(unc_path):
        parent = ntpath.dirname(unc_path)
        filename = ntpath.basename(unc_path)
        file_url = "file:///" + parent.replace("\\", "/")
        return Markup(f'<a href="{file_url}" title="Open folder">{markup_escape(parent)}</a>\\{markup_escape(filename)}')

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["dir_link"] = _dir_link
    template = env.get_template("template.html")
    html = template.render(
        report=report,
        severity_summary=report.severity_summary(),
        category_summary=report.category_summary(),
        sorted_findings=_sorted_findings(report),
        directory_priorities=_directory_priorities(report),
        version=__version__,
    )
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

def generate_json_report(report: ScanReport, output_path: str) -> None:
    data = {
        "target_host": report.result.target_host,
        "transport_method": report.result.transport_method,
        "scan_user": report.result.scan_user,
        "start_time": report.result.start_time,
        "end_time": report.result.end_time,
        "duration_seconds": report.result.duration_seconds,
        "total_files_scanned": report.result.total_files_scanned,
        "total_files_skipped": report.result.total_files_skipped,
        "severity_summary": report.severity_summary(),
        "category_summary": report.category_summary(),
        "findings": [asdict(f) for f in _sorted_findings(report)],
        "skipped_files": [asdict(s) for s in report.result.skipped_files],
    }
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
