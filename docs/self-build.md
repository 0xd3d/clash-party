# Building this fork

Use Node.js **22.12 or newer** and the version of pnpm pinned in `package.json` (**11.8.0**). The build host's Node.js version is separate from Electron's embedded runtime. These instructions cover modern Windows and macOS builds; they do not establish Windows 7 or macOS 10 compatibility.

## Updates stay in the fork

The update repository is resolved once at build time, in this order:

1. `CLASH_PARTY_UPDATE_REPOSITORY`, when set, as a GitHub `owner/repo` name.
2. `GITHUB_REPOSITORY`, provided by GitHub Actions.
3. `package.json` → `repository`, currently `0xd3d/clash-party`, for local builds.

The same resolver is used by the main process, renderer and release-note download-link generator. Invalid repository values fail the build instead of selecting another source. Update metadata, asset checksum API, installer downloads and the update dialog's release page all use that repository. Cached installers are checked against that repository's checksum before reuse.

The updater reads stable releases: `releases/latest/download/latest.yml`, then assets under `releases/download/v<version>/`. It does not fall back to upstream when the fork has no release. In that case checking for updates can report an error, and no installer is selected. A future intentionally published fork release needs a newer version, its `latest.yml`, the correctly named installer/archive and its `.sha256` file. A locally generated package or an Actions artifact alone is not an update release. The `dev` prerelease channel is not consumed by the application updater.

## GitHub Actions: artifacts only

The workflow file must first exist on the fork's default branch for `workflow_dispatch` to be available; adding it only to `feature/macos-dns-lifecycle` does not enable the Run workflow button. See [GitHub's manual workflow requirements](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow). Merging this file later is separate from creating a Release, and this change does not dispatch a run.

Once that prerequisite is satisfied, open **Actions → Self build (artifacts only) → Run workflow** in your fork and select the branch containing your changes. The workflow uses Windows and macOS runners, each preparing resources for its own OS and target architecture. It builds x64 and arm64 packages and retains the downloadable artifacts for seven days.

This workflow needs no signing secrets. It has read-only repository permissions, uploads artifacts, and neither deletes dev assets nor creates a Release. Do not run the existing **Build** workflow or push a `v*` tag merely to validate a self-build: that original publishing workflow is unchanged and can publish releases.

Windows installers are unsigned. The macOS app has an ad-hoc signature; its PKG is unsigned and is not notarized. These are self-use artifacts, not trusted public distribution packages. Before installing on your own machine, verify the downloaded checksum and establish trust through the operating system's normal controls. Public distribution needs your own appropriate signing certificates and, for macOS, notarization. Do not reuse upstream signing identities or credentials.

## Local builds

Build Windows packages on Windows and macOS packages on macOS. `scripts/prepare.mjs` selects the OS from the process running it; specifying an architecture does not change that OS. Preparing resources on macOS and then requesting a Windows package does not prepare Windows sidecars.

On a matching x64 or arm64 host, run:

```sh
pnpm install --frozen-lockfile
pnpm run review
pnpm test
```

The install runs the repository's existing prepare/postinstall hooks to download sidecars and install Electron dependencies. Do not hand-edit `extra/sidecar/` or `node_modules/.temp/`.

For Windows PowerShell, choose the target architecture before installation, for example:

```powershell
$env:npm_config_arch = 'x64'
$env:npm_config_target_arch = 'x64'
$env:CSC_IDENTITY_AUTO_DISCOVERY = 'false'
pnpm install --frozen-lockfile
pnpm run build:win --x64
```

For macOS, for example:

```sh
export npm_config_arch=arm64
export npm_config_target_arch=arm64
export CSC_IDENTITY_AUTO_DISCOVERY=false
pnpm install --frozen-lockfile
chmod +x build/pkg-scripts/preinstall build/pkg-scripts/postinstall
pnpm run build:mac --arm64 -c.mac.identity=-
```

Use `x64` instead on an Intel target. An explicit local update-source override can be set before building, for example `CLASH_PARTY_UPDATE_REPOSITORY=your-owner/your-fork`; use PowerShell's `$env:` syntax on Windows. Both build scripts pass `--publish never`.

The Actions workflow also places the `PORTABLE` marker inside the Windows portable archive. When preparing portable archives manually, include that marker at the archive root before use; the raw `7z` target alone does not add it.

## Installation and verification boundaries

Building and inspecting packages does not require stopping the installed application. Do not execute an installer or either PKG installation script while preserving an active session.

The macOS package retains the existing application identity and installation behavior. It replaces `/Applications/Clash Party.app`, installs the shared `party.mihomo.helper` under `/Library/PrivilegedHelperTools`, reloads its LaunchDaemon, and sets privileged core permissions. It is a replacement installation, not a separate app that can safely run beside upstream. Installing can interrupt an existing app or helper. Wait for a maintenance window and keep a copy of the current configuration before intentionally replacing it.

Safe build-time checks include tests with mocked DNS/helper calls, main/renderer compilation, package contents, Mach-O/PE architecture, plist syntax and static signature inspection. Native module loading must additionally be checked using the corresponding target OS and Electron runtime. Preparing an ARM64 package on an x64 runner is not proof that it runs on an ARM64 device.

Actual startup/exit, DNS restoration, TUN, network switching, sleep/wake and update installation require a disposable machine or VM where the app may be stopped and network settings may change. Source checks, successful packaging and checksum generation do not establish those runtime results.
