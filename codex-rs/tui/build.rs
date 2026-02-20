use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CODEX_CLI_VERSION");

    let Ok(pkg_version) = env::var("CARGO_PKG_VERSION") else {
        return;
    };

    if pkg_version != "0.0.0" {
        return;
    }

    // Allow callers (and tests) to override the embedded version without
    // relying on git metadata being available.
    if env::var_os("CODEX_CLI_VERSION").is_some() {
        return;
    }

    if let Some(version) = git_describe_version().and_then(|v| release_version(&v)) {
        println!("cargo:rustc-env=CODEX_CLI_VERSION={version}");
        return;
    }

    if let Some(version) = highest_release_tag(&["--merged", "HEAD", "--list", "rust-v*"]) {
        println!("cargo:rustc-env=CODEX_CLI_VERSION={version}");
        return;
    }

    if let Some(version) = highest_release_tag(&["--list", "rust-v*"]) {
        println!("cargo:rustc-env=CODEX_CLI_VERSION={version}");
    }
}

fn git_describe_version() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--match", "rust-v*", "--abbrev=0"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let tag = String::from_utf8(output.stdout).ok()?;
    tag_to_version(&tag)
}

fn highest_release_tag(args: &[&str]) -> Option<String> {
    let output = Command::new("git").arg("tag").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let mut best: Option<((u64, u64, u64), String)> = None;
    for tag in stdout.lines().map(str::trim).filter(|t| !t.is_empty()) {
        let Some(version) = tag_to_version(tag) else {
            continue;
        };
        let Some(parsed) = parse_plain_semver(&version) else {
            continue;
        };
        if is_release_triplet(parsed) {
            match &best {
                Some((best_triplet, _)) if *best_triplet >= parsed => {}
                _ => best = Some((parsed, version)),
            }
        }
    }
    best.map(|(_, v)| v)
}

fn tag_to_version(tag: &str) -> Option<String> {
    let tag = tag.trim();
    let version = tag.strip_prefix("rust-v")?;
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

fn release_version(version: &str) -> Option<String> {
    let parsed = parse_plain_semver(version)?;
    if is_release_triplet(parsed) {
        Some(version.to_string())
    } else {
        None
    }
}

fn is_release_triplet((major, minor, patch): (u64, u64, u64)) -> bool {
    // Treat 0.0.* tags as "non-release" so forks can add internal build tags
    // without breaking update checks which compare against upstream 0.x.y.
    (major, minor, patch) != (0, 0, 0) && !(major == 0 && minor == 0)
}

fn parse_plain_semver(version: &str) -> Option<(u64, u64, u64)> {
    let mut iter = version.split('.');
    let (Some(major), Some(minor), Some(patch)) = (iter.next(), iter.next(), iter.next()) else {
        return None;
    };
    if iter.next().is_some() {
        return None;
    }
    Some((
        major.parse::<u64>().ok()?,
        minor.parse::<u64>().ok()?,
        patch.parse::<u64>().ok()?,
    ))
}
