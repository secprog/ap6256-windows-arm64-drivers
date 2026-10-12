<!--
SPDX-License-Identifier: GPL-3.0-only
Licensed under the GNU General Public License, version 3 only.
Provided without warranty. See LICENSE for the license text.
-->

# SparkLAN AP6256 Windows ARM64 drivers

Source for the Wi-Fi driver, auxiliary SDIO function driver and Bluetooth UART
transport. The Wi-Fi driver supports WDI, WiFiCx and a diagnostic configuration.
Firmware patching code and its patch data are included. Firmware images, NVRAM,
CLM data and Bluetooth HCD files are supplied separately.

Version state is stored outside the source folder in
`$env:LOCALAPPDATA\AP6256\SourceVersions`. Use `-VersionCacheDirectory` to
choose another external cache. Keep that cache to preserve version assignments.
Generated version headers are written to the external output directory. Use
`build-source.ps1` for automatic source versioning; direct project builds use
the source default version.

Use a configured Windows Driver Kit or Enterprise Windows Driver Kit environment:

```powershell
.\build-source.ps1 -Driver wdi -OutputDirectory $env:TEMP\ap6256-wdi
.\build-source.ps1 -Driver wificx -OutputDirectory $env:TEMP\ap6256-wificx
.\build-source.ps1 -Driver fn -OutputDirectory $env:TEMP\ap6256-fn
.\build-source.ps1 -Driver bt -OutputDirectory $env:TEMP\ap6256-bt
```

`-HostCiphers` enables the extended station cipher build. `-PacketTrace` enables
packet diagnostics. Log Level defaults to Disabled. Build outputs stay outside
this source folder. Source builds are unsigned and do not include firmware or
install drivers.

To construct a firmware-containing package, add `-PackageFirmware` and
`-FirmwareDirectory` pointing to a separately supplied directory. Wi-Fi packaging
expects `4345r9rtecdc.bin`, `4345r9nvram.txt`
and `4345r9.clmb`. Bluetooth packaging expects `BCM4345C5.hcd`. Signing and device
installation are separate steps.

The [Build ARM64 drivers](.github/workflows/build-drivers.yml) workflow runs on
pushes, pull requests and manual dispatches. It uses the standard `windows-2022`
hosted runner with Visual Studio 2022, which is free for public repositories. No account secrets or
signing certificate are required. Microsoft SDK and ARM64 WDK NuGet packages
are pinned in `.github/scripts/packages.config` to the supported 10.0.26100
series and cached outside the checkout. All five driver
configurations build with code analysis and warnings treated as errors.

Download `ap6256-arm64-<version>-<run>` from the completed run's Artifacts
section. It contains the WDI, WiFiCx, diagnostic, SDIO function and Bluetooth
SYS/INF files, SHA-256 checksums, matching source and license texts. These
unsigned outputs require external firmware, catalog generation and signing
before installation. Driver artifacts expire after 30 days; failed builds do
not publish a driver artifact. Dependabot checks Actions and NuGet dependencies
weekly and groups SDK/WDK updates. The build reads package versions from the
manifest, and a manifest change participates in source versioning.

Project-authored source is licensed under GPL-3.0-only. Nine Bluetooth files
identified in NOTICE.txt retain MS-PL. See LICENSE, NOTICE.txt and
bt/LICENSE-MS-PL.txt for the file-level license scope.
The original Bluetooth code has the narrow combination permission described
in BLUETOOTH-LINKING-EXCEPTION.txt.
