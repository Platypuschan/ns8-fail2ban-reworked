#!/usr/bin/env python3
"""Open the module UI in cluster-admin and check that its tasks really run.

Runs on the CI runner (not in the VM) after ns8-smoke.sh, while the configured
instance still exists. Page headings render even when every module task fails,
so the check waits for values that only a completed get-configuration task can
fill in.
"""
import re
import sys
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

base_url, module, out_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
out_dir.mkdir(parents=True, exist_ok=True)

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_context(ignore_https_errors=True).new_page()
    page.set_default_timeout(30000)
    messages = []
    page.on("console", lambda message: messages.append(f"{message.type}: {message.text}"))
    try:
        page.goto(f"{base_url}/cluster-admin/")
        page.fill('text="Username"', "admin")
        page.click('button >> text="Continue"')
        page.fill('text="Password"', "Nethesis,1234")
        page.click('button >> text="Log in"')
        page.wait_for_selector("#main-content")

        page.goto(f"{base_url}/cluster-admin/#/apps/{module}")
        app = page.frame_locator("iframe")
        # Values written by ns8-smoke.sh/ns8-smoke.py: the coordinator URL and
        # the shared whitelist, which is editable only on a configured instance.
        public_url = app.locator('input[placeholder="https://bans.example.org"]')
        expect(public_url).to_have_value("https://bans.ns8.test", timeout=60000)
        whitelist = app.locator('textarea[placeholder^="192.0.2.0/24"]')
        expect(whitelist).to_be_enabled()
        expect(whitelist).to_have_value(re.compile(r"(^|\n)192\.0\.2\.0/24($|\n)"))
        expect(app.locator(".bx--inline-notification--error")).to_have_count(0)
        page.screenshot(path=str(out_dir / "ui-settings.png"), full_page=True)
        print("PASS: module UI loads its configuration in cluster-admin", flush=True)
    except Exception:
        page.screenshot(path=str(out_dir / "ui-failure.png"), full_page=True)
        (out_dir / "ui-console.log").write_text("\n".join(messages) + "\n")
        raise
    finally:
        browser.close()
