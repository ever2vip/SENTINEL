# GitHub Windows release

The **SENTINEL Enterprise V1.0 release** workflow runs on `windows-latest`.
It builds the source on the runner, runs the product and engine test programs,
packages the self-contained Windows x64 applications, and verifies installation,
the maintenance service, desktop first launch, upgrade, and uninstall.

This workflow does not consume or modify the existing local release files.
Its Windows build can produce different bytes from an earlier Linux-built
installer; the generated `SHA256SUMS.txt` identifies the CI distributables.

## Download an Actions build

1. Open the repository on GitHub and select **Actions**.
2. Select **SENTINEL Enterprise V1.0 release**.
3. Select **Run workflow**, choose `main`, and select **Run workflow** again.
4. Open the successful run and scroll to **Artifacts**.
5. Download **SENTINEL-Enterprise-V1.0-Windows-x64** and extract it.

The artifact contains `SENTINEL-Enterprise-V1.0-Setup-x64.exe` and
`SENTINEL-Enterprise-V1.0-Installer.zip`, plus distribution checksums and QA
metadata. The installer ZIP contains only Setup, README, and installer checksum.
Failed checks are retained in the separate **SENTINEL-Enterprise-V1.0-QA** artifact.

## Publish the V1.0 release

Push the `v1.0.0` tag to the source commit to start the release workflow.
After the Windows gate succeeds, the publication job creates
**SENTINEL Enterprise V1.0**, uploads both binaries, downloads the assets again,
and verifies their SHA-256 hashes before publishing the testing prerelease.
Open the repository's **Releases** page, select **SENTINEL Enterprise V1.0**,
and select either binary under **Assets** to download it directly.

The workflow refuses to overwrite an existing asset with different bytes.
It verifies that the tag still identifies the built source commit.
Installer binaries, build outputs, and local databases are excluded from Git
history; installer distribution uses Actions artifacts and Release assets.

The installer remains unsigned. Interactive acceptance on Windows 10 and 11,
including Demo Organization after installation and both themes, is still
required. A successful automated smoke gate does not replace that acceptance.
