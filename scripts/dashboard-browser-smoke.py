"""Optional real Chromium acceptance against an owned synthetic Flask fixture."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time


def read_startup(stream, timeout=30):
    deadline, data = time.monotonic() + timeout, bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise TimeoutError("Fixture startup handshake timed out")
        chunk = os.read(stream.fileno(), 4096)
        if not chunk:
            raise RuntimeError("Fixture exited before its startup handshake")
        data.extend(chunk)
        if len(data) > 4096:
            raise ValueError("Fixture startup handshake exceeds its bound")
        if b"\n" in data:
            startup = json.loads(bytes(data).split(b"\n", 1)[0])
            if (not isinstance(startup, dict) or type(startup.get("port")) is not int
                    or not 1 <= startup["port"] <= 65535 or not isinstance(startup.get("control_key"), str)
                    or len(startup["control_key"]) != 48):
                raise ValueError("Invalid fixture startup handshake")
            return startup


@contextmanager
def fixture_server(log):
    fixture = Path(__file__).with_name("dashboard-browser-fixture.py")
    # Parent cleanup also covers startup failure or forced termination of the child.
    with tempfile.TemporaryDirectory(prefix="ai-scanner-browser-db-") as directory:
        directory = str(Path(directory).resolve(strict=True))
        process = subprocess.Popen([sys.executable, str(fixture), "--directory", directory],
                                   stdout=subprocess.PIPE, stderr=log)
        try:
            yield process, read_startup(process.stdout), directory
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            process.stdout.close()


def contrast(first, second):
    def luminance(color):
        values = [int(value.strip()) / 255 for value in color[color.index("(") + 1:color.index(")")].split(",")[:3]]
        values = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4 for value in values]
        return sum(weight * value for weight, value in zip((.2126, .7152, .0722), values))
    low, high = sorted((luminance(first), luminance(second)))
    return (high + .05) / (low + .05)


def acceptance(base, control_key, artifacts):
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context(viewport=dict(width=1440, height=1050), service_workers="block")
            page = context.new_page()
            errors, external = [], []
            def local_only(route):
                if route.request.url.startswith(base + "/"):
                    route.continue_()
                else:
                    external.append(route.request.url)
                    route.abort()
            context.route("**/*", local_only)
            page.add_init_script("window.fixtureCsp=[];document.addEventListener('securitypolicyviolation',e=>window.fixtureCsp.push(e.violatedDirective))")
            page.on("pageerror", lambda error: errors.append(str(error)))

            def login():
                page.locator("#operatorKey").fill("browser-fixture-operator")
                page.locator("#operatorKey").press("Enter")
                expect(page.locator("#scanControls")).to_have_js_property("disabled", False)

            def open_scan(status):
                page.locator("#openScanId").fill("fixture-" + status)
                page.locator("#openScanId").press("Enter")
                expect(page.locator("#selectedScanId")).to_have_text("fixture-" + status)

            def wait_delayed():
                deadline = time.monotonic() + 5
                while not delayed and time.monotonic() < deadline:
                    page.wait_for_timeout(25)
                assert delayed, "Expected delayed fixture request did not arrive"

            page.goto(base + "/")
            login()
            # Capture the real controller only to exercise redundant polling without waiting.
            page.evaluate("const original=AIAgentScanner.prototype.poll;AIAgentScanner.prototype.poll=function(){window.fixtureController=this;return original.call(this)}")
            hints = dict(scanType="modelProbeHelp", networkRanges="scopeHelp networkHelp", repositories="scopeHelp pathHelp",
                         trafficSources="scopeHelp pathHelp", sourceScanId="sourceHelp modelProbeHelp",
                         modelOverrides="modelSelectionHelp modelProbeHelp")
            for identifier, expected in hints.items():
                actual = page.locator("#" + identifier).get_attribute("aria-describedby").split()
                assert set(expected.split()) <= set(actual), (identifier, actual)
                assert all(page.locator("#" + hint).text_content().strip() for hint in actual)
            announcement = page.locator("#scanAnnouncement")
            for attribute, value in (("role", "status"), ("aria-live", "polite"), ("aria-atomic", "true")):
                expect(announcement).to_have_attribute(attribute, value)
            open_scan("completed")
            expect(announcement).to_contain_text("Scan completed.")
            expect(announcement).to_contain_text("Review incomplete checks and evidence.")
            expect(page.locator("#riskScore")).to_have_text("Not assessed")
            expect(page.locator("#auditRegion")).to_have_attribute("role", "region")
            expect(page.locator("#auditRegion")).to_have_attribute("aria-labelledby", "auditTitle")
            expect(page.locator("#auditRegion")).to_have_attribute("tabindex", "0")
            page.evaluate("window.fixtureNotices=[];new MutationObserver(()=>window.fixtureNotices.push(document.querySelector('#scanAnnouncement').textContent)).observe(document.querySelector('#scanAnnouncement'),{childList:true,characterData:true,subtree:true})")
            details = page.locator("#assetList details").first
            details.locator("summary").click()
            checks = details.get_by_role("region", name="Check records for <fixture>", exact=True)
            expect(checks).to_have_attribute("tabindex", "0")
            expect(checks.locator(".check-record")).to_have_count(18)
            more = details.get_by_role("button", name="Show more checks")
            more.focus()
            page.keyboard.press("Enter")
            expect(more).to_be_hidden()
            expect(checks).to_be_focused()
            expect(checks.locator(".check-record")).to_have_count(36)
            page.evaluate("window.fixtureController.poll()")
            page.evaluate("window.fixtureController.poll()")
            expect(checks).to_be_focused()
            assert page.evaluate("window.fixtureNotices") == []

            open_scan("completed")
            expect(page.locator("#reportView")).to_be_visible()
            details = page.locator("#assetList details").first
            details.locator("summary").click()
            page.locator("#scanName").focus()
            details.locator("button").evaluate("node=>node.click()")
            expect(page.locator("#scanName")).to_be_focused()
            open_scan("partial")
            expect(announcement).to_contain_text("partial results")
            expect(page.locator("#riskScore")).to_have_text("70.0 / 100 (partial coverage)")
            expect(page.locator("#assetList")).to_contain_text("Risk: 70.0 / 100 (partial coverage)")
            expect(page.locator("#findingList")).to_contain_text("Synthetic protected disclosure")
            details = page.locator("#assetList details").first
            details.locator("summary").click()
            more = details.locator("button")
            for _ in range(5):
                more.focus()
                page.keyboard.press("Enter")
            expect(more).to_be_hidden()
            expect(details.get_by_role("region")).to_be_focused()
            expect(details.locator(".check-record")).to_have_count(100)
            expect(details).to_contain_text("Showing 100 of 110 checks")
            for status in ("failed", "cancelled", "interrupted"):
                open_scan(status)
                expect(announcement).to_contain_text("Scan " + status + ".")
                assert "passed" not in announcement.inner_text().lower()

            open_scan("finding-groups")
            expect(page.locator("#findingGroupingSummary")).to_contain_text("7 finding groups / 18 sample occurrences")
            expect(page.locator("#findingCount")).to_have_text("18")
            expect(page.locator("#riskScore")).to_have_text("70.0 / 100")
            expect(page.locator("#findingList .finding-groups > article")).to_have_count(7)
            expect(page.locator("#findingList .finding-occurrences pre")).to_have_count(0)
            expect(page.locator("#findingList img")).to_have_count(0)
            expect(page.locator("#findingList article").first).to_contain_text("<img src=x onerror=alert(1)>")
            records = page.locator("#findingList details").first
            records.locator("summary").focus()
            page.keyboard.press("Enter")
            expect(records.locator("pre")).to_have_count(3)
            saved_records = [json.loads(text) for text in records.locator("pre").all_text_contents()]
            assert [record["id"] for record in saved_records] == [f"fixture-0-{index}" for index in range(3)]
            expect(records.get_by_role("button", name="Show more occurrences")).to_be_hidden()
            records.get_by_role("region").focus()
            page.evaluate("window.fixtureController.poll()")
            expect(records.get_by_role("region")).to_be_focused()
            expect(records).to_have_attribute("open", "")
            for width in (1440, 390, 320):
                page.set_viewport_size(dict(width=width, height=1050 if width == 1440 else 844))
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                page.screenshot(path=str(artifacts / f"finding-groups-{width}.png"), full_page=True)
            page.set_viewport_size(dict(width=1440, height=1050))

            open_scan("finding-cap")
            groups = page.locator("#findingList .finding-groups")
            more = page.get_by_role("button", name="Show more finding groups", exact=True)
            expect(groups.locator(":scope > article")).to_have_count(18)
            expect(page.locator("#findingGroupingSummary")).to_contain_text("110 finding groups / 110 sample occurrences")
            for _ in range(5):
                more.focus()
                page.keyboard.press("Enter")
            expect(more).to_be_hidden()
            expect(groups).to_be_focused()
            expect(groups.locator(":scope > article")).to_have_count(100)
            expect(page.locator("#findingList")).to_contain_text("Showing 100 of 110 finding groups")

            open_scan("occurrence-cap")
            records = page.locator("#findingList details").first
            records.locator("summary").click()
            expect(records.locator("pre")).to_have_count(18)
            assert len(records.locator("pre").first.text_content()) == 16384
            expect(records).to_contain_text("Record preview truncated")
            more = records.get_by_role("button", name="Show more occurrences", exact=True)
            for _ in range(5):
                more.focus()
                page.keyboard.press("Enter")
            expect(more).to_be_hidden()
            expect(records.get_by_role("region")).to_be_focused()
            expect(records.locator("pre")).to_have_count(100)
            expect(records).to_contain_text("Showing 100 of 110 occurrences")

            open_scan("running")
            expect(page.locator("#scanStatus")).to_have_text("running")
            expect(announcement).to_be_empty()
            page.locator("#scanName").focus()
            response = context.request.post(base + "/fixture/state", headers={"X-Fixture-Key": control_key},
                                            data=dict(id="fixture-running", status="completed"))
            assert response.ok, response.text()
            expect(announcement).to_contain_text("Scan completed.", timeout=6000)
            expect(page.locator("#scanName")).to_be_focused()
            page.route("**/api/scans/fixture-failed/results", lambda route: route.fulfill(status=503,
                content_type="application/json", body=json.dumps(dict(error="Synthetic report unavailable"))))
            open_scan("failed")
            expect(announcement).to_contain_text("Scan failed. Report unavailable.")
            expect(page.locator("#notice")).to_contain_text("Synthetic report unavailable")
            expect(page.locator("#jsonBtn")).to_be_disabled()
            page.unroute("**/api/scans/fixture-failed/results")
            page.evaluate("window.fixtureController.poll()")
            expect(announcement).to_contain_text("Scan failed. Report available.")
            expect(page.locator("#notice")).not_to_contain_text("Synthetic report unavailable")
            page.evaluate("window.fixtureNotices=[]")
            page.evaluate("window.fixtureController.poll()")
            assert page.evaluate("window.fixtureNotices") == []
            page.route("**/api/scans/fixture-interrupted/results", lambda route: route.fulfill(status=200,
                content_type="application/json", body=json.dumps(dict(results=dict(pipeline=None)))))
            open_scan("interrupted")
            expect(announcement).to_contain_text("No versioned report is available. Testing completeness is unverified.")
            expect(page.locator("#notice")).to_contain_text("This scan has no versioned report")
            expect(page.locator("#jsonBtn")).to_be_disabled()
            page.unroute("**/api/scans/fixture-interrupted/results")

            # Delay a real response across selection and logout to verify epoch guards.
            delayed = []
            pattern = "**/api/scans/fixture-completed/results"
            page.route(pattern, lambda route: delayed.append(route))
            open_scan("completed")
            wait_delayed()
            open_scan("partial")
            expect(announcement).to_contain_text("partial results")
            expect(page.locator("#notice")).not_to_contain_text("This scan has no versioned report")
            for route in delayed:
                route.continue_()
            delayed.clear()
            page.wait_for_timeout(100)
            expect(announcement).to_contain_text("partial results")
            page.evaluate("window.fixtureController.notice('Unrelated operator action.');window.fixtureController.poll()")
            expect(page.locator("#notice")).to_have_text("Unrelated operator action.")

            page.locator("#scanName").focus()
            colors = page.locator("#scanName").evaluate("n=>{const s=getComputedStyle(n);return {border:s.borderColor,bg:s.backgroundColor,focus:s.outlineColor,width:s.outlineWidth,style:s.outlineStyle}}")
            assert contrast(colors["border"], colors["bg"]) >= 3
            assert contrast(colors["focus"], colors["bg"]) >= 3
            assert colors["width"] != "0px" and colors["style"] != "none"
            for width in (1440, 390, 320):
                page.set_viewport_size(dict(width=width, height=1050 if width == 1440 else 844))
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                page.screenshot(path=str(artifacts / f"dashboard-{width}.png"), full_page=True)
            open_scan("completed")
            wait_delayed()
            page.locator("#logoutBtn").click()
            for route in delayed:
                try:
                    route.continue_()
                except Exception:
                    pass  # The authenticated request may already have been aborted.
            page.unroute(pattern)
            expect(announcement).to_be_empty()
            expect(page.locator("#reportView")).to_be_hidden()
            expect(page.locator("#findingList")).to_be_empty()
            expect(page.locator("#findingGroupingSummary")).to_be_empty()
            expect(page.locator("#operatorKey")).to_be_focused()
            login()
            page.route(pattern, lambda route: route.fulfill(status=401,
                content_type="application/json", body=json.dumps(dict(error="Synthetic session expired"))))
            open_scan("completed")
            expect(page.locator("#scanControls")).to_have_js_property("disabled", True)
            expect(announcement).to_be_empty()
            expect(page.locator("#reportView")).to_be_hidden()
            expect(page.locator("#operatorKey")).to_be_focused()
            assert page.evaluate("localStorage.length + sessionStorage.length") == 0
            assert page.evaluate("window.fixtureCsp") == []
            assert not errors, errors
            assert not external, external
            return dict(status="passed", border_contrast=contrast(colors["border"], colors["bg"]),
                        focus_contrast=contrast(colors["focus"], colors["bg"]), artifacts=str(artifacts))
        finally:
            browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path, help="New directory for screenshots and fixture logs (must not exist)")
    parser.add_argument("--fail-after-start", action="store_true", help="Deliberately fail to verify fixture cleanup")
    args = parser.parse_args()
    artifacts = args.artifacts_dir.resolve() if args.artifacts_dir else Path(tempfile.mkdtemp(prefix="ai-scanner-browser-"))
    if args.artifacts_dir:
        artifacts.mkdir(parents=False, exist_ok=False)
    def stop(*_):
        raise SystemExit("Browser smoke interrupted")
    previous = signal.signal(signal.SIGTERM, stop)
    try:
        with (artifacts / "fixture.log").open("x") as log, fixture_server(log) as (process, startup, directory):
            base = f"http://127.0.0.1:{startup['port']}"
            print(json.dumps(dict(fixture_pid=process.pid, fixture_url=base,
                                  database_directory=directory, artifacts=str(artifacts))), flush=True)
            if args.fail_after_start:
                raise AssertionError("Deliberate failure for fixture cleanup verification")
            print(json.dumps(acceptance(base, startup["control_key"], artifacts), indent=2))
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    main()
