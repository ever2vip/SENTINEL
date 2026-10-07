#!/usr/bin/env python3
"""Publish only the verified V1.1.1 artifacts, without replacing existing assets."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import quote

VERSION = "1.1.1"
TAG = "v" + VERSION
RELEASE_VERSION = VERSION[:-2] if VERSION.endswith(".0") else VERSION
TITLE = "SENTINEL Enterprise V" + RELEASE_VERSION
EXE = f"SENTINEL-Enterprise-V{RELEASE_VERSION}-Setup-x64.exe"
ZIP = f"SENTINEL-Enterprise-V{RELEASE_VERSION}-Installer.zip"
FILES = [EXE, ZIP, "README.txt", "SHA256SUMS.txt", "release-manifest.json",
         "verification-results.json", "desktop-verification-results.json"]


def invoke(*arguments: str, stdout=None) -> str:
    result = subprocess.run(["gh", *arguments], stdout=stdout or subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError("GitHub operation failed: " + " ".join(arguments[:2]) + "; " + error)
    return "" if stdout else result.stdout.decode("utf-8")


def api(endpoint: str) -> dict:
    return json.loads(invoke("api", endpoint))


def mutate(endpoint: str, method: str, payload: dict) -> dict:
    # Structured JSON keeps literal newlines and credentials out of shell commands.
    with tempfile.TemporaryDirectory() as directory:
        body = Path(directory) / "request.json"
        body.write_text(json.dumps(payload), encoding="utf-8")
        return json.loads(invoke("api", endpoint, "--method", method, "--input", str(body)))


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def find_release(repository: str) -> dict | None:
    # Listing with write access finds existing drafts as well as public releases.
    pages = json.loads(invoke("api", "--paginate", "--slurp",
                              f"repos/{repository}/releases?per_page=100"))
    matches = [release for page in pages for release in page if release["tag_name"] == TAG]
    if len(matches) > 1:
        raise RuntimeError("Multiple releases use v1.1.1; resolve them before publication.")
    return matches[0] if matches else None


def refresh(repository: str, release_id: int, names: set[str] | None = None) -> dict:
    # Read-only bounded retries tolerate GitHub asset-list eventual consistency.
    # Release creation itself is never repeated after an ambiguous response.
    for attempt in range(6):
        release = api(f"repos/{repository}/releases/{release_id}")
        if names is None or names.issubset({asset["name"] for asset in release["assets"]}):
            return release
        if attempt < 5:
            time.sleep(min(2 ** attempt, 8))
    raise RuntimeError("Uploaded assets are unavailable through the release ID; leaving the draft unpublished.")


def download(repository: str, asset: dict, destination: Path) -> None:
    # Download by immutable asset ID, including private draft assets. Using gh
    # preserves its authentication and redirect handling without exposing tokens.
    with destination.open("wb") as stream:
        invoke("api", f"repos/{repository}/releases/assets/{asset['id']}",
               "--header", "Accept: application/octet-stream", stdout=stream)


def upload(repository: str, release_id: int, name: str, path: Path) -> dict:
    # The upload API uses uploads.github.com rather than api.github.com. Send
    # the workflow-scoped token only to that explicit trusted host; do not depend
    # on gh having separate credentials configured for the upload hostname.
    endpoint = f"/repos/{repository}/releases/{release_id}/assets?name={quote(name, safe='')}"
    connection = http.client.HTTPSConnection("uploads.github.com", timeout=120)
    try:
        with path.open("rb") as stream:
            connection.request("POST", endpoint, body=stream, headers={
                "Authorization": "Bearer " + os.environ["GH_TOKEN"],
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "SENTINEL-release-verifier",
                "Content-Type": "application/octet-stream",
                "Content-Length": str(path.stat().st_size),
            })
            response = connection.getresponse()
            payload = response.read()
        if response.status != 201:
            raise RuntimeError(f"GitHub release asset upload failed for {name}: HTTP {response.status}. Draft retained; nothing overwritten.")
        return json.loads(payload)
    finally:
        connection.close()


def verify_distribution(directory: Path, source: str) -> dict[str, str]:
    expected = {}
    for name in FILES:
        path = directory / name
        if not path.is_file():
            raise RuntimeError("Missing distribution file: " + name)
        expected[name] = digest(path)
    declarations = {}
    for line in (directory / "SHA256SUMS.txt").read_text(encoding="ascii").splitlines():
        checksum, name = line.split("  ", 1)
        if name in declarations:
            raise RuntimeError("Duplicate binary checksum declaration: " + name)
        declarations[name] = checksum
    if declarations != {name: expected[name] for name in [EXE, ZIP]}:
        raise RuntimeError("Distribution checksums do not match both binaries.")
    manifest = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8-sig"))
    if manifest["sourceCommit"] != source or manifest["version"] != VERSION:
        raise RuntimeError("The manifest does not identify V1.1.1 and the commit built by this tag run.")
    windows = json.loads((directory / "verification-results.json").read_text(encoding="utf-8-sig"))
    checks = {check["name"]: check for check in windows["checks"]}
    if len(checks) != len(windows["checks"]):
        raise RuntimeError("Windows verification has duplicate check names; refusing ambiguous acceptance.")
    required = ["installer-exists", "installer-is-pe", "silent-install",
                "service-account-and-start", "service-health", "service-boundaries",
                "start-menu-and-uninstall", "desktop-first-launch", "same-version-upgrade", "silent-uninstall",
                "installed-desktop-functional-and-rendered-acceptance",
                "installed-desktop-keeps-upgrade-profile-unchanged",
                "upgraded-silent-uninstall-preserves-evidence",
                "v1.0-upgraded-silent-uninstall-preserves-evidence"]
    for baseline in ["v1.0", "v1.1"]:
        required.extend([f"public-{baseline}-baseline-hash", f"public-{baseline}-install",
                         f"public-{baseline}-demo-settings-dpapi-seed",
                         f"{baseline}-to-v{RELEASE_VERSION}-in-place-upgrade",
                         f"{baseline}-data-settings-secret-and-audit-bytes-preserved",
                         f"v{RELEASE_VERSION}-reads-original-{baseline}-demo-settings-and-dpapi",
                         f"{baseline}-upgraded-service-account-and-health"])
    if any(check["status"] == "failed" for check in checks.values()):
        raise RuntimeError("Windows verification contains failing checks.")
    if any(checks.get(name, {}).get("status") != "passed" for name in required):
        raise RuntimeError("A required installation, V1.0/V1.1 upgrade or installed desktop gate did not pass.")
    installer = [item for item in manifest["files"] if item["path"].replace("\\", "/") == EXE]
    if (len(installer) != 1 or installer[0]["sha256"] != expected[EXE]
            or installer[0]["sizeBytes"] != (directory / EXE).stat().st_size):
        raise RuntimeError("The distributed installer does not match the packaged manifest.")
    desktop = json.loads((directory / "desktop-verification-results.json").read_text(encoding="utf-8-sig"))
    if (desktop.get("status") != "passed" or desktop.get("failed") != 0
            or desktop.get("quick") is not False or len(desktop.get("renders", [])) < 360
            or desktop.get("dispatcherFailures")):
        raise RuntimeError("The complete installed desktop functional/rendered acceptance matrix did not pass.")
    desktop_checks = {check["Name"]: check for check in desktop.get("checks", [])}
    if desktop_checks.get("render-matrix-physical-screenshot-completeness", {}).get("Status") != "passed":
        raise RuntimeError("The installed desktop did not verify all 360 matrix screenshots physically exist.")
    assembly = [item for item in manifest["files"] if item["path"].replace("\\", "/").endswith("/Desktop/Sentinel.Desktop.dll")]
    if len(assembly) != 1 or desktop["desktopAssemblySha256"] != assembly[0]["sha256"]:
        raise RuntimeError("Desktop acceptance did not exercise the application assembly in this installer payload.")
    return expected


def publish(directory: Path, repository: str, source: str) -> dict:
    expected = verify_distribution(directory, source)
    reference = api(f"repos/{repository}/git/ref/tags/{TAG}")["object"]
    while reference["type"] == "tag":
        reference = api(f"repos/{repository}/git/tags/{reference['sha']}")["object"]
    if reference["type"] != "commit" or reference["sha"] != source:
        raise RuntimeError("The v1.1.1 tag moved after the build; refusing publication.")
    notes = (
        "SENTINEL Enterprise V1.1.1 — reporting and evidence consistency fixes.\n\n"
        "Executive recommendations follow the same contextual remediation ranking as the plan; "
        "risk-reduction estimates use consistent displayed precision. Defensive attack paths require "
        "evidence that covers the asset relationship. Existing local evidence and preferences are preserved.\n\n"
        "Self-contained unsigned Windows 10/11 x64 testing installer. Visual Studio, source code, "
        "a separately installed .NET runtime, Docker and an external database server are not required.\n\n"
        "The Release build, product and engine tests, installed WPF functional/rendered acceptance, "
        "service/install/uninstall smoke gates, and upgrades from the original public V1.0 and V1.1 installers passed. "
        "The upgrade gate preserves the original evidence, settings, history, audit records and user-bound "
        "DPAPI fixture, plus V1.1 desktop planning/review metadata. See attached verification results and the Actions QA artifact. Physical Windows "
        "10/11 and native display scaling acceptance remain distinct manual checks.\n\n"
        "Both Release binaries and all supporting assets were downloaded by immutable asset ID and "
        "SHA-256 verified before publication. This CI build does not promise byte-for-byte reproducibility "
        "with an earlier build. V1.0 and V1.1 tags and release assets remain unchanged.\n"
    )
    release = find_release(repository)
    if release is None:
        # Use the create response's immutable release ID immediately. Do not query
        # the eventually-consistent release collection to discover the new draft.
        release = mutate(f"repos/{repository}/releases", "POST", {
            "tag_name": TAG, "target_commitish": source, "name": TITLE,
            "body": notes, "draft": True, "prerelease": True,
        })
        if not release.get("id") or release.get("tag_name") != TAG or not release.get("draft"):
            raise RuntimeError("GitHub did not return the expected draft release; refusing publication.")
    elif release["name"] != TITLE or not release["prerelease"]:
        raise RuntimeError("An existing V1.1.1 release has different metadata; refusing to modify it.")
    release_id = release["id"]
    assets = {asset["name"]: asset for asset in release["assets"]}
    with tempfile.TemporaryDirectory() as temporary:
        downloads = Path(temporary)
        # Verify every existing asset before any upload. Never clobber differing
        # bytes, never modify historical V1.0/V1.1 releases, and never move a published version's tag.
        for name in FILES:
            if name in assets:
                destination = downloads / name
                download(repository, assets[name], destination)
                if digest(destination) != expected[name]:
                    raise RuntimeError("Existing Release asset has different bytes: " + name +
                                       ". Nothing was overwritten; use a new version for a new build.")
        for name in FILES:
            if name not in assets:
                created = upload(repository, release_id, name, directory / name)
                if created.get("name") != name or not created.get("id"):
                    raise RuntimeError("Upload did not return the expected asset: " + name)
                destination = downloads / name
                download(repository, created, destination)
                if digest(destination) != expected[name]:
                    raise RuntimeError("Downloaded Release asset checksum mismatch: " + name)
        release = refresh(repository, release_id, set(FILES))
    if release["draft"]:
        published = mutate(f"repos/{repository}/releases/{release_id}", "PATCH", {
            "draft": False, "prerelease": True, "name": TITLE, "body": notes,
        })
    else:
        published = refresh(repository, release_id, set(FILES))
    if published["draft"] or not published["prerelease"] or published["tag_name"] != TAG:
        raise RuntimeError("Release did not enter the expected published V1.1.1 prerelease state.")
    published_assets = {asset["name"]: asset for asset in published["assets"]}
    lines = ["## Verified SENTINEL Enterprise V1.1.1 Release", "", published["html_url"], ""]
    for name in [EXE, ZIP]:
        if name not in published_assets:
            raise RuntimeError("Published Release is missing a verified binary: " + name)
        lines.extend([f"**{name}**", published_assets[name]["browser_download_url"],
                      f"SHA-256: {expected[name]}", ""])
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write("\n".join(lines))
    print("Release assets downloaded and SHA-256 verified; V1.1.1 testing prerelease published.")
    print(published["html_url"])
    return published


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path("distribution"))
    options = parser.parse_args()
    publish(options.directory.resolve(), os.environ["GH_REPO"], os.environ["SENTINEL_SOURCE_COMMIT"])
