# Fork releases (GitHub Releases)

This fork ships Windows `codex self-update` binaries via GitHub Releases.

## Cutting a release

Releases are normally automated by the scheduled workflow in `.github/workflows/auto-sync-upstream-release.yml`,
which watches upstream `openai/codex` stable releases and publishes a corresponding `fork-vX.Y.Z` release with
Windows assets.

Use the manual flow below only if automation is blocked (for example, an upstream merge conflict).

1. Create and push an annotated tag:

   ```bash
   git tag -a fork-v0.104.1 -m "fork release 0.104.1"
   git push metyatech fork-v0.104.1
   ```

   Pre-releases use a suffix after the `X.Y.Z` version (for example `fork-v0.104.1-alpha.1`).

2. GitHub Actions builds Windows binaries and publishes a GitHub Release with assets:
   - `codex-x86_64-pc-windows-msvc.exe`
   - `codex-command-runner-x86_64-pc-windows-msvc.exe`
   - `codex-windows-sandbox-setup-x86_64-pc-windows-msvc.exe`

## Update checks

Update checks compare the latest GitHub Release tag (`fork-vX.Y.Z`) against the embedded CLI version. To trigger an update prompt, the new release must be a higher `X.Y.Z` than the installed version.
