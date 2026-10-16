use std::{
    env,
    path::{Path, PathBuf},
};

pub fn app_data_directory() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("SECRET_D_DATA_DIR") {
        return Ok(PathBuf::from(path));
    }
    app_data_directory_from(
        env::var_os("HOME"),
        env::var_os("XDG_DATA_HOME"),
        cfg!(target_os = "macos"),
    )
}

fn app_data_directory_from(
    home: Option<std::ffi::OsString>,
    xdg_data_home: Option<std::ffi::OsString>,
    macos: bool,
) -> Result<PathBuf, String> {
    let home = home.ok_or_else(|| "HOME is not set".to_string())?;
    if macos {
        return Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("secretd"));
    }
    Ok(xdg_data_home
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".local").join("share"))
        .join("secretd"))
}

pub fn default_vault_path() -> Result<PathBuf, String> {
    Ok(app_data_directory()?.join("vault.json"))
}

pub fn default_runtime_path() -> Result<PathBuf, String> {
    Ok(app_data_directory()?.join("runtime.json"))
}

pub fn default_settings_path() -> Result<PathBuf, String> {
    Ok(app_data_directory()?.join("settings.json"))
}

pub fn cli_runtime_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("SECRET_D_RUNTIME") {
        return Ok(PathBuf::from(path));
    }
    default_runtime_path()
}

pub fn ensure_parent(path: &Path) -> Result<&Path, String> {
    path.parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_existing_platform_paths() {
        let home = Some("/Users/example".into());
        assert_eq!(
            app_data_directory_from(home.clone(), None, true).unwrap(),
            PathBuf::from("/Users/example/Library/Application Support/secretd")
        );
        assert_eq!(
            app_data_directory_from(home, None, false).unwrap(),
            PathBuf::from("/Users/example/.local/share/secretd")
        );
    }
}
