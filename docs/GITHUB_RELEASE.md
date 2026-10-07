# GitHub Windows release

The **SENTINEL Enterprise V1.1 release** workflow runs on `windows-latest`.
It builds the source on the runner, runs the product and engine test programs,
packages the self-contained Windows x64 applications, and verifies installation,
the maintenance service, desktop first launch, same-version repair, and uninstall.
The gate also installs the unchanged public V1.0 release, creates genuine V1.0
Demo evidence/settings/history and user-bound DPAPI data using its installed
assemblies, upgrades in place, and checks byte and semantic continuity.
The installed V1.1 WPF assemblies run the functional and rendered acceptance
harness using isolated QA data.

This workflow does not consume or modify the existing local release files.
Its Windows build can produce different bytes from an earlier Linux-built
installer; the generated `SHA256SUMS.txt` identifies the CI distributables.

## Download an Actions build

1. Open the repository on GitHub and select **Actions**.
2. Select **SENTINEL Enterprise V1.1 release**.
3. Select **Run workflow**, choose `main`, and select **Run workflow** again.
4. Open the successful run and scroll to **Artifacts**.
5. Download **SENTINEL-Enterprise-V1.1-Windows-x64** and extract it.

The artifact contains `SENTINEL-Enterprise-V1.1-Setup-x64.exe` and
`SENTINEL-Enterprise-V1.1-Installer.zip`, plus distribution checksums and QA
metadata. The installer ZIP contains only Setup, README, and installer checksum.
Failed checks are retained in the separate **SENTINEL-Enterprise-V1.1-QA** artifact.

## Publish the V1.1 release

Push the `v1.1.0` tag to the source commit to start the release workflow.
After all Windows gates succeed, the publication job creates
**SENTINEL Enterprise V1.1**, uploads both binaries, downloads the assets again,
and verifies their SHA-256 hashes before publishing the testing prerelease.
Draft creation uses the returned immutable release ID, so publication does not
depend on an immediately consistent release collection. Asset downloads use
immutable asset IDs; bounded read-only retries tolerate asset-list propagation.
No differing asset is overwritten, including drafts from an interrupted run.
Open the repository's **Releases** page, select **SENTINEL Enterprise V1.1**,
and select either binary under **Assets** to download it directly.

The workflow refuses to overwrite an existing asset with different bytes.
It verifies that the tag still identifies the built source commit.
The historical `v1.0.0` tag and assets are preserved.
Installer binaries, build outputs, and local databases are excluded from Git
history; installer distribution uses Actions artifacts and Release assets.

The installer remains unsigned. Interactive acceptance on Windows 10 and 11,
at native desktop DPI and on physical Windows 10 remains required.
The rendered matrix explicitly records simulated 100%/125%/150% scaling; it
does not claim that the hosted Windows runner changed its native system DPI.
QA artifacts retain screenshots, layout findings, functional results, installer
helper diagnostics and any failed checks. No failed gate may publish a release.
