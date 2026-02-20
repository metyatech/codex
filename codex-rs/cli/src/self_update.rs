use anyhow::Context as _;
use codex_core::default_client::create_client;
use serde_json::Value;
use std::path::Path;
use std::path::PathBuf;

const GITHUB_REPO: &str = "metyatech/codex";
const LATEST_RELEASE_API_URL: &str = "https://api.github.com/repos/metyatech/codex/releases/latest";

#[cfg(target_arch = "x86_64")]
const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
#[cfg(target_arch = "aarch64")]
const WINDOWS_TARGET: &str = "aarch64-pc-windows-msvc";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported Windows architecture for self-update");

#[derive(Debug, clap::Args)]
pub struct SelfUpdateCommand {
    /// PID to wait on before overwriting binaries.
    ///
    /// When omitted, this defaults to the current process PID so `codex self-update`
    /// works when invoked directly by users.
    #[arg(long = "parent-pid")]
    pub parent_pid: Option<u32>,
}

#[derive(Debug, clap::Args)]
pub struct SelfUpdateApplyCommand {
    /// PID to wait on before overwriting binaries.
    #[arg(long = "parent-pid")]
    pub parent_pid: u32,

    /// Directory where `codex.exe` is installed (the updater will replace binaries next to it).
    #[arg(long = "install-dir", value_name = "DIR")]
    pub install_dir: PathBuf,
}

pub async fn run_self_update(cmd: SelfUpdateCommand) -> anyhow::Result<()> {
    let parent_pid = cmd.parent_pid.unwrap_or(std::process::id());
    let current_exe = std::env::current_exe().context("failed to resolve current exe path")?;
    let install_dir = current_exe
        .parent()
        .map(Path::to_path_buf)
        .context("current exe has no parent directory")?;

    let tmp_root = std::env::temp_dir().join(format!("codex-self-update-{parent_pid}"));
    std::fs::create_dir_all(&tmp_root).with_context(|| {
        format!(
            "failed to create self-update temp directory at {tmp_root}",
            tmp_root = tmp_root.display()
        )
    })?;
    let updater_exe = tmp_root.join("codex-self-update-updater.exe");
    std::fs::copy(&current_exe, &updater_exe).with_context(|| {
        format!(
            "failed to copy updater binary from {current_exe} to {updater_exe}",
            current_exe = current_exe.display(),
            updater_exe = updater_exe.display()
        )
    })?;

    std::process::Command::new(&updater_exe)
        .arg("self-update-apply")
        .arg("--parent-pid")
        .arg(parent_pid.to_string())
        .arg("--install-dir")
        .arg(&install_dir)
        .spawn()
        .with_context(|| {
            format!(
                "failed to spawn updater at {updater_exe}",
                updater_exe = updater_exe.display()
            )
        })?;

    Ok(())
}

pub async fn run_self_update_apply(cmd: SelfUpdateApplyCommand) -> anyhow::Result<()> {
    wait_for_pid_exit(cmd.parent_pid)?;
    apply_latest_github_release(&cmd.install_dir).await
}

fn wait_for_pid_exit(pid: u32) -> anyhow::Result<()> {
    // SAFETY: Uses Win32 APIs with correct signatures and checks return values.
    unsafe {
        type Handle = *mut core::ffi::c_void;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const INFINITE: u32 = 0xFFFF_FFFF;
        const WAIT_FAILED: u32 = 0xFFFF_FFFF;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> Handle;
            fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
            fn CloseHandle(handle: Handle) -> i32;
        }

        let handle = OpenProcess(SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            return Ok(());
        }

        let res = WaitForSingleObject(handle, INFINITE);
        let _ = CloseHandle(handle);
        if res == WAIT_FAILED {
            anyhow::bail!("WaitForSingleObject failed while waiting for PID {pid}");
        }

        Ok(())
    }
}

async fn apply_latest_github_release(install_dir: &Path) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(install_dir)
        .await
        .with_context(|| {
            format!(
                "failed to create install directory at {install_dir}",
                install_dir = install_dir.display()
            )
        })?;

    eprintln!("Checking latest release for {GITHUB_REPO}...");
    let release = create_client()
        .get(LATEST_RELEASE_API_URL)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("failed to query GitHub Releases API")?
        .error_for_status()
        .context("GitHub Releases API returned an error status")?
        .json::<Value>()
        .await
        .context("failed to parse GitHub Releases JSON")?;

    let assets = release
        .get("assets")
        .and_then(Value::as_array)
        .context("release JSON missing `assets` array")?;

    let codex_asset_name = format!("codex-{WINDOWS_TARGET}.exe");
    let command_runner_asset_name = format!("codex-command-runner-{WINDOWS_TARGET}.exe");
    let sandbox_setup_asset_name = format!("codex-windows-sandbox-setup-{WINDOWS_TARGET}.exe");

    let assets_to_install = [
        (&codex_asset_name, install_dir.join("codex.exe")),
        (
            &command_runner_asset_name,
            install_dir.join("codex-command-runner.exe"),
        ),
        (
            &sandbox_setup_asset_name,
            install_dir.join("codex-windows-sandbox-setup.exe"),
        ),
    ];

    for (asset_name, dest_path) in assets_to_install {
        let url = assets
            .iter()
            .find_map(|asset| {
                let name = asset.get("name").and_then(Value::as_str)?;
                if name != asset_name {
                    return None;
                }
                asset
                    .get("browser_download_url")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .with_context(|| {
                let available: Vec<&str> = assets
                    .iter()
                    .filter_map(|asset| asset.get("name").and_then(Value::as_str))
                    .collect();
                format!(
                    "missing expected release asset {asset_name}; available assets: {available:?}",
                )
            })?;

        eprintln!("Downloading {asset_name}...");
        let body = create_client()
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failed to download {asset_name} from {url}"))?
            .error_for_status()
            .with_context(|| format!("download failed for {asset_name} from {url}"))?
            .bytes()
            .await
            .with_context(|| format!("failed to read download body for {asset_name}"))?;

        let dest_file_name = dest_path
            .file_name()
            .context("destination path has no file name")?
            .to_string_lossy();
        let staged_path =
            dest_path.with_file_name(format!("{dest_file_name}.new.{}", std::process::id()));
        let _ = tokio::fs::remove_file(&staged_path).await;
        tokio::fs::write(&staged_path, &body)
            .await
            .with_context(|| {
                format!(
                    "failed to write {asset_name} to {staged_path}",
                    staged_path = staged_path.display()
                )
            })?;

        install_binary(&staged_path, &dest_path).with_context(|| {
            format!(
                "failed to install {asset_name} to {dest_path}",
                dest_path = dest_path.display()
            )
        })?;
    }

    eprintln!("Update complete. Restart Codex to use the new version.");
    Ok(())
}

fn install_binary(staged_path: &Path, dest_path: &Path) -> anyhow::Result<()> {
    let dest_dir = dest_path
        .parent()
        .context("destination path has no parent directory")?;
    std::fs::create_dir_all(dest_dir).with_context(|| {
        format!(
            "failed to create destination directory {dest_dir}",
            dest_dir = dest_dir.display()
        )
    })?;

    let mut backup_path = None;
    if dest_path.exists() {
        let file_name = dest_path
            .file_name()
            .context("destination path has no file name")?
            .to_string_lossy();
        let backup = dest_path.with_file_name(format!("{file_name}.old.{}", std::process::id()));
        backup_path = Some(backup.clone());

        // Best-effort: keep a backup for debugging if overwrite fails.
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(dest_path, &backup).with_context(|| {
            format!(
                "failed to move existing binary from {dest_path} to {backup_path}",
                dest_path = dest_path.display(),
                backup_path = backup.display()
            )
        })?;
    }

    std::fs::rename(staged_path, dest_path).with_context(|| {
        format!(
            "failed to move downloaded binary from {staged_path} to {dest_path}",
            staged_path = staged_path.display(),
            dest_path = dest_path.display()
        )
    })?;

    if let Some(backup_path) = backup_path {
        let _ = std::fs::remove_file(backup_path);
    }

    Ok(())
}
