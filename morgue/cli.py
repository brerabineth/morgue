"""morgue CLI - scan, forge, ioc.

Exit codes:
  0  success
  2  usage / input error
  3  scan failed (unreadable path, nothing parseable)
  10 scan succeeded and exposure reached --fail-on threshold
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, forge as forge_mod, report as report_mod, scanner, terminal

THRESHOLDS = ("clean", "low", "medium", "high", "critical")
_BAND_INDEX = {b: i for i, b in enumerate(THRESHOLDS)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="morgue",
        description="local triage for infostealer logs - nothing leaves the machine",
    )
    parser.add_argument("--version", action="version", version="morgue " + __version__)
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a log directory (single victim or a folder of logs)")
    p_scan.add_argument("path", help="directory containing the log(s)")
    p_scan.add_argument("--outdir", default="morgue-out", help="where reports are written (default: ./morgue-out)")
    p_scan.add_argument("--corp", action="append", default=[],
                        help="corporate domain to flag; repeatable (e.g. --corp acme.com)")
    p_scan.add_argument("--family", choices=("", "redline", "lumma", "stealc", "rhadamanthys", "generic"),
                        default="", help="force family instead of fingerprinting")
    p_scan.add_argument("--reveal", action="store_true",
                        help="write plaintext passwords/cookies to reports (default: masked)")
    p_scan.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p_scan.add_argument("--fail-on", choices=THRESHOLDS, default="",
                        help="exit 10 when exposure band >= threshold (for automation)")
    p_scan.add_argument("--quiet", action="store_true", help="suppress terminal summary")

    p_forge = sub.add_parser("forge", help="generate a synthetic (fake) stealer log for training/tests")
    p_forge.add_argument("--out", default="forge-out", help="output directory (default: ./forge-out)")
    p_forge.add_argument("--family", choices=("redline", "lumma", "stealc"), default="lumma")
    p_forge.add_argument("--seed", type=int, default=1337)
    p_forge.add_argument("--creds", type=int, default=40)
    p_forge.add_argument("--cookies", type=int, default=30)

    p_ioc = sub.add_parser("ioc", help="write a JSONL intel feed from a scan (no secrets by design)")
    p_ioc.add_argument("path", help="directory containing the log(s)")
    p_ioc.add_argument("--out", default="iocs.jsonl")
    p_ioc.add_argument("--corp", action="append", default=[])
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "forge":
        try:
            root = forge_mod.forge(args.out, family=args.family, seed=args.seed,
                                   creds=args.creds, cookies=args.cookies)
        except ValueError as exc:
            print("forge: %s" % exc, file=sys.stderr)
            return 2
        print("forged %s log at %s (seed %d)" % (args.family, root, args.seed))
        return 0

    if args.command == "scan":
        try:
            scan = scanner.scan_path(args.path, corp_domains=args.corp,
                                     family_hint=args.family)
        except FileNotFoundError as exc:
            print("scan: %s" % exc, file=sys.stderr)
            return 2
        except OSError as exc:
            print("scan: %s" % exc, file=sys.stderr)
            return 3
        if not scan.bundles:
            print("scan: nothing parseable found under %s" % args.path, file=sys.stderr)
            for w in scan.warnings:
                print("  %s" % w, file=sys.stderr)
            return 3
        if not args.quiet:
            print(terminal.render(scan, color=not args.no_color))
        try:
            report_mod.write_json(scan, os.path.join(args.outdir, "report.json"), reveal=args.reveal)
            report_mod.write_csv(scan, os.path.join(args.outdir, "credentials.csv"), reveal=args.reveal)
            report_mod.write_html(scan, os.path.join(args.outdir, "report.html"), reveal=args.reveal)
        except OSError as exc:
            print("scan: report write failed: %s" % exc, file=sys.stderr)
            return 3
        print("reports written to %s (report.json, credentials.csv, report.html)" % args.outdir)
        if args.fail_on:
            threshold = _BAND_INDEX[args.fail_on]
            actual = _BAND_INDEX[scan.score.band]
            if actual >= threshold:
                return 10
        return 0

    if args.command == "ioc":
        try:
            scan = scanner.scan_path(args.path, corp_domains=args.corp)
        except FileNotFoundError as exc:
            print("ioc: %s" % exc, file=sys.stderr)
            return 2
        try:
            report_mod.write_iocs(scan, args.out)
        except OSError as exc:
            print("ioc: write failed: %s" % exc, file=sys.stderr)
            return 3
        print("%d victim record(s) -> %s" % (len(scan.bundles), args.out))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
