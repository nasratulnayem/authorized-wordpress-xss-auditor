#!/usr/bin/env python3
"""AutoXSS - authorized XSS automation helper."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List
from urllib.parse import quote, urljoin, urlparse


class Colors:
    """ANSI color codes for a hacker-style UI."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"


BANNER = f"""
{Colors.CYAN}     ___        __        _  __  __
    / _ | ___  / /____ __| |/_/ / _/ ___
   / __ |/ _ \\/ __/ _ `/ _>  <  / _/ / _ \\
  /_/ |_|\\___/\\__/\\_,_/|_/_/|_|/_/   \\___/
{Colors.RESET}
             {Colors.BOLD}AutoXSS{Colors.RESET} :: {Colors.YELLOW}precision payload runner{Colors.RESET}
""".strip("\n")


def _load_payloads(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {path}")
    raw = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    payloads = []
    for line in raw:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        payloads.append(line)
    if not payloads:
        raise ValueError("No payloads loaded (file empty or only comments)")
    return payloads


def _build_url(base: str, payload: str, encode: bool) -> str:
    # This function now assumes base has a '=' and will replace the value after the last '='
    if "{payload}" in base:
        injected = quote(payload, safe="") if encode else payload
        return base.replace("{payload}", injected)

    if "=" not in base:
        return base + (quote(payload, safe="") if encode else payload)

    # Re-assemble URL with payload injected after the last '='
    parts = base.split("=")
    base_part = "=".join(parts[:-1]) + "="
    final_payload = quote(payload, safe="") if encode else payload
    return base_part + final_payload


def _discover_payload_files(cwd: Path) -> List[Path]:
    files = sorted({p for p in cwd.glob("*.txt") if p.is_file() and p.name != "success.txt"})
    if not files:
        raise ValueError("No .txt payload files found in the current directory")
    return files


def _require_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(
            f"{Colors.RED}Playwright is required. Install with: pip install playwright && playwright install{Colors.RESET}"
        ) from exc
    return sync_playwright


def _discover_injectable_urls(sync_playwright, base_url: str) -> List[str]:
    """Crawl a base URL to find GET parameters."""
    print(f"{Colors.YELLOW}[*] No injection point in URL, starting discovery on {base_url}{Colors.RESET}")
    urls_found = set()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)
            page.goto(base_url, wait_until="domcontentloaded", timeout=15000)

            base_domain = urlparse(base_url).netloc

            for a in page.query_selector_all("a"):
                try:
                    href = a.get_attribute("href")
                    if not href or href.strip().startswith(("javascript:", "mailto:")):
                        continue

                    abs_url = urljoin(base_url, href.strip())
                    parsed_url = urlparse(abs_url)

                    if parsed_url.netloc == base_domain and "=" in parsed_url.query:
                        # Rebuild URL to be clean, ensuring we have a valid param structure
                        urls_found.add(f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{parsed_url.query}")
                except Exception:
                    continue
            browser.close()
    except Exception as e:
        print(f"{Colors.RED}[!] Discovery failed: {e}{Colors.RESET}")
        return []

    if not urls_found:
        print(f"{Colors.YELLOW}[-] No injectable URLs with '=' found on the entry page.{Colors.RESET}")
        return []

    print(f"{Colors.GREEN}[+] Discovery finished. Found {len(urls_found)} potential target(s).{Colors.RESET}")
    return sorted(list(urls_found))


def run(
    target_urls: List[str],
    payload_files: List[Path],
    *,
    timeout_ms: int,
    wait_ms: int,
    encode: bool,
) -> int:
    sync_playwright = _require_playwright()

    file_payloads = [(p, _load_payloads(p)) for p in payload_files]
    total_payloads = sum(len(pl) for _, pl in file_payloads)
    total_tests = len(target_urls) * total_payloads
    hits = 0
    fails = 0

    # Initialize seen_success_urls set and prepare success.txt
    seen_success_urls: set[str] = set()
    out_path = Path("success.txt")
    if out_path.exists():
        seen_success_urls.update(out_path.read_text(encoding="utf-8").strip().splitlines())
    
    print(BANNER)
    print(f"{Colors.CYAN}Targets: {len(target_urls)}{Colors.RESET}")
    print(f"{Colors.CYAN}Payload files: {len(payload_files)}{Colors.RESET}")
    print(f"{Colors.CYAN}Total Payloads: {total_payloads}{Colors.RESET}")
    print(f"{Colors.CYAN}Total Tests: {total_tests}{Colors.RESET}")
    print(f"{Colors.CYAN}Mode: JS-alert detection (Playwright){Colors.RESET}")
    print(f"{Colors.BLUE}" + "-" * 60 + f"{Colors.RESET}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        
        test_idx = 0
        for base_url in target_urls:
            print(f"{Colors.YELLOW}[*] Testing target: {base_url}{Colors.RESET}")
            
            payload_idx = 0
            for file_path, payloads in file_payloads:
                print(f"  {Colors.CYAN}[>] Using payload file: {file_path.name}{Colors.RESET}")
                for payload in payloads:
                    test_idx += 1
                    payload_idx += 1
                    url = _build_url(base_url, payload, encode)
                    page = context.new_page()
                    alert_fired = False

                    def on_dialog(dialog):
                        nonlocal alert_fired
                        alert_fired = True
                        try:
                            dialog.accept()
                        except Exception:
                            pass

                    page.on("dialog", on_dialog)

                    try:
                        page.goto(url, wait_until="load", timeout=timeout_ms)
                        if wait_ms:
                            page.wait_for_timeout(wait_ms)
                    except Exception:
                        pass
                    finally:
                        page.close()

                    if alert_fired:
                        hits += 1
                        status = f"{Colors.GREEN}SUCCESS{Colors.RESET}"
                        if url not in seen_success_urls:
                            with open(out_path, "a", encoding="utf-8") as f:
                                f.write(url + "\n")
                            seen_success_urls.add(url)
                    else:
                        fails += 1
                        status = f"{Colors.RED}FAILED{Colors.RESET}"

                    print(f"[{test_idx:04d}/{total_tests:04d}] {status} :: {url}")

        browser.close()

    print(f"{Colors.BLUE}" + "-" * 60 + f"{Colors.RESET}")
    print(f"Done. {Colors.GREEN}Success: {hits}{Colors.RESET} | {Colors.RED}Failed: {fails}{Colors.RESET}")

    if hits > 0:
        print(f"{Colors.GREEN}[+] All unique successes saved incrementally to: {out_path}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[-] No successes to save.{Colors.RESET}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}AutoXSS{Colors.RESET} - authorized XSS payload automation",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "base_url",
        nargs="?",
        help="Target URL. If it lacks a '=', discovery mode will be activated.",
    )
    parser.add_argument(
        "payload_file",
        nargs="?",
        help="Optional: Path to a single payload list (.txt). If omitted, all .txt files are used.",
    )
    parser.add_argument("--timeout", type=int, default=10000, help="Navigation timeout (ms)")
    parser.add_argument("--wait", type=int, default=1000, help="Post-load wait (ms)")
    parser.add_argument("--encode", action="store_true", help="URL-encode payloads")

    args = parser.parse_args()

    if not args.base_url:
        args.base_url = input(f"{Colors.YELLOW}Target URL: {Colors.RESET}").strip()

    # Sanitize input URL by removing surrounding quotes
    args.base_url = args.base_url.strip("'\" ")
    
    target_urls: List[str]

    try:
        sync_playwright = _require_playwright()
        
        if "=" not in args.base_url and "{payload}" not in args.base_url:
            target_urls = _discover_injectable_urls(sync_playwright, args.base_url)
            if not target_urls:
                return 1
        else:
            target_urls = [args.base_url]

        if args.payload_file:
            payload_files = [Path(args.payload_file)]
        else:
            payload_files = _discover_payload_files(Path.cwd())
        
        return run(
            target_urls,
            payload_files,
            timeout_ms=args.timeout,
            wait_ms=args.wait,
            encode=args.encode,
        )
    except (ValueError, FileNotFoundError) as exc:
        print(f"{Colors.RED}[!] Error: {exc}{Colors.RESET}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"{Colors.RED}[!] Runtime Error: {exc}{Colors.RESET}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] User interrupted. Exiting.{Colors.RESET}")
        return 130
    except Exception as exc:
        print(f"{Colors.RED}[!] An unexpected error occurred: {exc}{Colors.RESET}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
