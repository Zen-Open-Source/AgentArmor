use std::path::Path;

#[derive(Debug, Default)]
pub struct PermCheck {
    pub exists: bool,
    pub mode: String,
    pub is_group_readable: bool,
    pub is_world_readable: bool,
    pub is_owner_only: bool,
}

pub fn check_permissions(path: &Path) -> PermCheck {
    use std::os::unix::fs::PermissionsExt;

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return PermCheck { exists: false, ..Default::default() },
    };

    let mode = meta.permissions().mode() & 0o777;
    let group_bits = (mode >> 3) & 0o7;
    let world_bits = mode & 0o7;

    PermCheck {
        exists: true,
        mode: format!("{:o}", mode),
        is_group_readable: (group_bits & 0o4) != 0,
        is_world_readable: (world_bits & 0o4) != 0,
        is_owner_only: group_bits == 0 && world_bits == 0,
    }
}

/// Recursively find credential files under base_path/credentials/
pub fn find_credential_files(base_path: &Path) -> Vec<std::path::PathBuf> {
    let cred_dir = base_path.join("credentials");
    if !cred_dir.exists() {
        return vec![];
    }

    walkdir::WalkDir::new(&cred_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name().to_string_lossy();
            name.ends_with(".json")
                || name.ends_with(".key")
                || name.ends_with(".pem")
                || name.ends_with(".token")
        })
        .map(|e| e.into_path())
        .collect()
}

/// Find agent auth-profile files under base_path/agents/*/agent/auth-profiles.json
pub fn find_auth_profiles(base_path: &Path) -> Vec<std::path::PathBuf> {
    let agents_dir = base_path.join("agents");
    if !agents_dir.exists() {
        return vec![];
    }

    let Ok(entries) = std::fs::read_dir(&agents_dir) else {
        return vec![];
    };

    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path().join("agent").join("auth-profiles.json"))
        .filter(|p| p.exists())
        .collect()
}
