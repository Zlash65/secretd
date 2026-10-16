use std::{fs, io::ErrorKind, path::Path};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::paths::ensure_parent;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Appearance {
    #[default]
    System,
    Light,
    Dark,
}

/// A page of the main window.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Page {
    #[default]
    Aws,
    Credentials,
    Grants,
    Activity,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub appearance: Appearance,
    /// The page the main window opens on: the one it showed last.
    pub page: Page,
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self, String> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| format!("{} is not a valid settings file", path.display())),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.to_string()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let directory = ensure_parent(path)?;
        let temporary = directory.join(format!(".secretd-settings-{}.tmp", Uuid::new_v4()));
        let mut contents = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        contents.push(b'\n');
        let result = fs::write(&temporary, contents)
            .and_then(|()| fs::rename(&temporary, path))
            .map_err(|error| error.to_string());
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_settings_follow_the_system_appearance() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::load(&directory.path().join("settings.json")).unwrap();
        assert_eq!(settings, Settings::default());
        assert_eq!(settings.appearance, Appearance::System);
        assert_eq!(settings.page, Page::Aws);
    }

    #[test]
    fn saves_and_reloads_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let settings = Settings {
            appearance: Appearance::Dark,
            page: Page::Grants,
        };
        settings.save(&path).unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "{\n  \"appearance\": \"dark\",\n  \"page\": \"grants\"\n}\n"
        );
        assert_eq!(Settings::load(&path).unwrap(), settings);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn settings_without_a_page_open_aws_sso() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, r#"{"appearance": "light"}"#).unwrap();

        let settings = Settings::load(&path).unwrap();
        assert_eq!(settings.appearance, Appearance::Light);
        assert_eq!(settings.page, Page::Aws);
    }

    #[test]
    fn rejects_unknown_appearances() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, r#"{"appearance": "sepia"}"#).unwrap();
        assert!(Settings::load(&path).is_err());
    }
}
