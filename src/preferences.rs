use gpui_kit::{App, Global};

use secretd::{paths::default_settings_path, settings::Settings};

struct Preferences(Settings);

impl Global for Preferences {}

/// Reads the saved settings, falling back to the defaults when they cannot be read.
pub fn load(cx: &mut App) {
    let settings = default_settings_path()
        .and_then(|path| Settings::load(&path))
        .unwrap_or_else(|error| {
            eprintln!("Could not load secretd settings: {error}");
            Settings::default()
        });
    cx.set_global(Preferences(settings));
}

pub fn settings(cx: &App) -> &Settings {
    &cx.global::<Preferences>().0
}

/// Applies `change` and saves the settings if it changed them.
pub fn update(cx: &mut App, change: impl FnOnce(&mut Settings)) -> Result<(), String> {
    let settings = &mut cx.global_mut::<Preferences>().0;
    let previous = settings.clone();
    change(settings);
    if *settings == previous {
        return Ok(());
    }
    default_settings_path().and_then(|path| settings.save(&path))
}
