#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import argparse
import sys
import os

SEVERITY_MAP = {
    "none":     0,
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}
SEVERITY_LABEL = {v: k.upper() for k, v in SEVERITY_MAP.items()}
SEVERITY_COLOR = {
    0: "",
    1: "\033[33m",
    2: "\033[93m",
    3: "\033[91m",
    4: "\033[95m",
}
RESET = "\033[0m"


def severity_label(sev_int, color=True):
    label = SEVERITY_LABEL.get(sev_int, "UNKNOWN")
    if color and sys.stdout.isatty():
        c = SEVERITY_COLOR.get(sev_int, "")
        return f"{c}{label}{RESET}"
    return label


def parse_severity(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def load_tree(nessus_file):
    if not os.path.exists(nessus_file):
        print(f"[ERROR] File not found: {nessus_file}")
        sys.exit(1)
    try:
        tree = ET.parse(nessus_file)
        return tree.getroot()
    except ET.ParseError as e:
        print(f"[ERROR] Failed to parse XML: {e}")
        sys.exit(1)


def build_sev_filter(severities):
    if not severities:
        return None
    sev_filter = set()
    for s in severities:
        s_lower = s.lower()
        if s_lower not in SEVERITY_MAP:
            print(f"[ERROR] Unknown severity '{s}'. Valid: {', '.join(SEVERITY_MAP)}")
            sys.exit(1)
        sev_filter.add(SEVERITY_MAP[s_lower])
    return sev_filter


def extract_vulnerable_hosts(nessus_file, plugin_name=None, plugin_id=None,
                              severities=None, output_file=None):
    print(f"[*] Reading file: {nessus_file}")
    root = load_tree(nessus_file)
    sev_filter = build_sev_filter(severities)

    results = []
    seen = set()

    for report_host in root.iter("ReportHost"):
        host_ip = report_host.get("name", "")
        for tag in report_host.iter("tag"):
            if tag.get("name") == "host-ip":
                host_ip = tag.text
                break

        for item in report_host.iter("ReportItem"):
            pid   = item.get("pluginID", "")
            pname = item.get("pluginName", "")
            port  = item.get("port", "")
            sev   = parse_severity(item.get("severity", "0"))

            plugin_match = False
            if plugin_id and str(plugin_id) == pid:
                plugin_match = True
            if plugin_name and plugin_name.lower() in pname.lower():
                plugin_match = True
            if not plugin_id and not plugin_name:
                plugin_match = True

            sev_match = (sev_filter is None) or (sev in sev_filter)

            if plugin_match and sev_match:
                key = (host_ip, port, pid)
                if key not in seen:
                    seen.add(key)
                    results.append((host_ip, port, pname, sev))

    if not results:
        print("[!] No vulnerable hosts found with the given filters.")
        if plugin_name or plugin_id:
            print("    Tip: verify the plugin name/ID with --list-plugins")
        return

    results.sort(key=lambda x: (-x[3], x[0], int(x[1]) if x[1].isdigit() else 0))

    # Group results by (plugin_name, severity) and print header once per group
    from itertools import groupby
    keyfn = lambda x: (x[3], x[2])  # sort key: sev desc already applied
    print(f"\n[+] {len(results)} result(s) found:\n")
    current_group = None
    for host, port, pname, sev in results:
        group = (pname, sev)
        if group != current_group:
            label = severity_label(sev)
            print(f"[{label}] {pname}")
            current_group = group
        print(f"{host}:{port}")

    if output_file:
        written = set()
        lines = []
        for host, port, _, _ in results:
            entry = f"{host}:{port}"
            if entry not in written:
                written.add(entry)
                lines.append(entry)
        with open(output_file, "w") as f:
            for l in lines:
                f.write(l + "\n")
        print(f"\n[+] {len(lines)} unique host:port entries saved to: {output_file}")


def list_plugins(nessus_file, severities=None):
    root = load_tree(nessus_file)
    sev_filter = build_sev_filter(severities)

    plugins = {}
    for item in root.iter("ReportItem"):
        pid   = item.get("pluginID", "")
        pname = item.get("pluginName", "")
        sev   = parse_severity(item.get("severity", "0"))
        if pid not in plugins:
            if sev_filter is None or sev in sev_filter:
                plugins[pid] = (pname, sev)

    if not plugins:
        print("[!] No plugins found with the given severity filter.")
        return

    sorted_plugins = sorted(plugins.items(), key=lambda x: (-x[1][1], x[1][0].lower()))

    print(f"\n[*] {len(plugins)} plugin(s) found in scan:\n")
    for pid, (pname, sev) in sorted_plugins:
        label = severity_label(sev)
        print(f"  [{pid:<7}]  [{label:<8}]  {pname}")


if __name__ == "__main__":
    # Pre-process sys.argv: pull out the .nessus file BEFORE argparse runs
    # This prevents nargs="+" flags (like --severity) from consuming it
    raw_args = sys.argv[1:]
    nessus_file = None
    filtered_args = []

    for token in raw_args:
        if (not token.startswith("-")
                and nessus_file is None
                and (token.endswith(".nessus") or
                     (os.path.isfile(token) and "." in os.path.basename(token)))):
            nessus_file = token
        else:
            filtered_args.append(token)

    # Argparse so no positional file argument needed
    parser = argparse.ArgumentParser(
        description="Extract vulnerable hosts (host:port) from .nessus scan files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Severity levels (highest to lowest): critical, high, medium, low, none

The .nessus file can go ANYWHERE in the command.

Examples:
  python3 extract_nessus.py --list-plugins --severity critical high scan.nessus
  python3 extract_nessus.py scan.nessus --plugin-name "sweet32"
  python3 extract_nessus.py scan.nessus --plugin-id 42873 --output sweet32.txt
  python3 extract_nessus.py --severity critical --output critical.txt scan.nessus
  python3 extract_nessus.py --severity critical high --output out.txt scan.nessus
  python3 extract_nessus.py scan.nessus --plugin-name "sweet32" --severity high critical
  python3 extract_nessus.py scan.nessus --list-plugins --severity critical high
        """
    )

    parser.add_argument("--plugin-name", help="Plugin name or partial name, e.g. 'sweet32'")
    parser.add_argument("--plugin-id", type=int, help="Numeric Nessus plugin ID")
    parser.add_argument(
        "--severity", "-s",
        nargs="+",
        metavar="LEVEL",
        help="Severity filter (space-separated): none low medium high critical"
    )
    parser.add_argument("--output", "-o", help="Output file -- one host:port per line")
    parser.add_argument("--list-plugins", action="store_true",
                        help="List all plugins found in the file (combine with --severity to filter)")

    args = parser.parse_args(filtered_args)

    if not nessus_file:
        parser.print_usage()
        print("\n[ERROR] No .nessus file specified.")
        sys.exit(1)

    if args.list_plugins:
        list_plugins(nessus_file, severities=args.severity)
        sys.exit(0)

    if not args.plugin_name and not args.plugin_id and not args.severity:
        print("[ERROR] Provide at least one filter: --plugin-name, --plugin-id, or --severity")
        print("        Use --list-plugins to explore available plugins.")
        sys.exit(1)

    extract_vulnerable_hosts(
        nessus_file=nessus_file,
        plugin_name=args.plugin_name,
        plugin_id=args.plugin_id,
        severities=args.severity,
        output_file=args.output,
    )
