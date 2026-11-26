"""
render_worker.py - renders a web page in headless Chromium (Playwright) and saves
a full-page PNG screenshot and a PDF. Run as a separate process by app.py so a
browser crash can never take the web app down.

    python render_worker.py <url> <output_dir> <file_prefix>

Prints ONE line of JSON describing the result. Every network request the browser
makes (including redirects and sub-resources) is checked with netguard, so a page
cannot be used to reach private/internal addresses.
"""
import os
import sys
import json
from datetime import datetime, timezone

from netguard import is_allowed_url

ALLOW_PRIVATE = os.environ.get("OSINT_ALLOW_PRIVATE", "0") == "1"
USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Acquisition-Tool/1.2 rendered-capture)"


def main():
    url, outdir, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(json.dumps({"ok": False, "error": "Playwright is not installed. Run: pip install playwright "
                                                 "and then: playwright install chromium"}))
        return

    png = os.path.join(outdir, f"{prefix}_screenshot.png")
    pdf = os.path.join(outdir, f"{prefix}_page.pdf")
    blocked, result = [], {"ok": False}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport={"width": 1280, "height": 800},
                                      user_agent=USER_AGENT, accept_downloads=False)
            page = ctx.new_page()

            def guard(route):
                target = route.request.url
                if target.split(":", 1)[0] in ("data", "blob", "about") or is_allowed_url(target, ALLOW_PRIVATE):
                    route.continue_()
                else:
                    blocked.append(target[:200])
                    route.abort()

            page.route("**/*", guard)
            resp = page.goto(url, wait_until="load", timeout=45000)
            try:
                page.wait_for_load_state("networkidle", timeout=10000)   # let late content settle
            except Exception:
                pass
            rendered_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            page.screenshot(path=png, full_page=True)
            pdf_ok = True
            try:
                page.pdf(path=pdf, format="A4", print_background=True)
            except Exception:
                pdf_ok = False
            result = {
                "ok": True, "final_url": page.url, "title": page.title(),
                "http_status": resp.status if resp else None, "rendered_at_utc": rendered_at,
                "browser": f"Chromium {browser.version}", "png": png,
                "pdf": pdf if pdf_ok and os.path.exists(pdf) else None,
                "blocked_requests": blocked,
            }
            browser.close()
    except Exception as e:
        result = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:300]}"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
