use gpui_kit::component::{ActiveTheme as _, Theme, ThemeMode, ThemeRegistry};
use gpui_kit::{App, Window, px};

use secretd::settings::Appearance;

use crate::preferences;

// Catppuccin Latte and Mocha from GPUI Component's theme set. Like Latte, Mocha uses a
// single accent, its own lavender, instead of upstream's mix of blue, mauve, and sapphire.
const CATPPUCCIN_THEMES: &str = r##"
{
  "name": "Catppuccin",
  "author": "Catppuccino",
  "url": "https://github.com/catppuccin/catppuccin",
  "themes": [
    {
      "name": "Catppuccin Latte",
      "mode": "light",
      "colors": {
        "accent.background": "#d3d8e0",
        "accent.foreground": "#4c4f69",
        "background": "#E5E9EF",
        "border": "#CCD0DA",
        "ring": "#7287fd",
        "foreground": "#4c4f69",
        "input.border": "#acb0be",
        "link.active.foreground": "#7287fd",
        "link.foreground": "#7287fd",
        "link.hover.foreground": "#7287fd",
        "list.active.background": "#7287fd22",
        "list.active.border": "#7287fd",
        "list.even.background": "#EFF1F5",
        "list.head.background": "#dce0e8",
        "muted.background": "#dce0e8",
        "muted.foreground": "#9a9db2",
        "panel.background": "#dce0e8",
        "primary.active.background": "#7287fd",
        "primary.background": "#7287fd",
        "primary.foreground": "#EFF1F5",
        "scrollbar.background": "#EFF1F500",
        "scrollbar.thumb.background": "#acb0be",
        "secondary.active.background": "#CCD2DE",
        "secondary.background": "#dce0e8",
        "secondary.foreground": "#4c4f69",
        "secondary.hover.background": "#CCD2DE99",
        "tab.active.background": "#E5E9EF",
        "tab.active.foreground": "#4c4f69",
        "tab.background": "#D2D7E200",
        "tab.foreground": "#82848c",
        "tab_bar.background": "#DCE0E8",
        "title_bar.background": "#DCE0E8",
        "title_bar.border": "#bec3d0",
        "base.red": "#d26a53",
        "base.green": "#5aa93b",
        "base.yellow": "#df8e1d",
        "base.blue": "#78acdc",
        "base.magenta": "#8778dc",
        "base.magenta.light": "#9978dc66",
        "base.cyan": "#53d2b0"
      }
    },
    {
      "name": "Catppuccin Mocha",
      "mode": "dark",
      "colors": {
        "accent.background": "#2e2e3e",
        "accent.foreground": "#cdd6f4",
        "background": "#181825",
        "border": "#313244",
        "ring": "#b4befe",
        "foreground": "#cdd6f4",
        "input.border": "#6c7086",
        "link.active.foreground": "#b4befe",
        "link.foreground": "#b4befe",
        "link.hover.foreground": "#b4befe",
        "list.active.background": "#b4befe22",
        "list.active.border": "#b4befe",
        "list.even.background": "#161622",
        "list.head.background": "#1E1E2E",
        "muted.background": "#302d41",
        "muted.foreground": "#6c7086",
        "panel.background": "#302d41",
        "popover.background": "#1e1e2e",
        "popover.foreground": "#cdd6f4",
        "primary.active.background": "#b4befe",
        "primary.background": "#b4befe",
        "primary.foreground": "#1e1e2e",
        "scrollbar.background": "#1e1e2e00",
        "scrollbar.thumb.background": "#4e4e5e",
        "secondary.active.background": "#45475a",
        "secondary.background": "#302d41",
        "secondary.foreground": "#cdd6f4",
        "secondary.hover.background": "#575268",
        "tab.background": "#0B0B1100",
        "tab.foreground": "#aeb7d5",
        "tab_bar.background": "#0B0B11",
        "title_bar.background": "#11111B",
        "title_bar.border": "#313244",
        "base.red": "#f38ba8",
        "base.green": "#a6e3a1",
        "base.yellow": "#f9e2af",
        "base.blue": "#89b4fa",
        "base.magenta": "#f5c2e7",
        "base.magenta.light": "#f38ba866",
        "base.cyan": "#94e2d5"
      }
    }
  ]
}
"##;

/// Colors for secretd's own surfaces, matched to the active Catppuccin flavor.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub background: u32,
    pub sidebar: u32,
    pub surface: u32,
    pub surface_muted: u32,
    pub ink: u32,
    pub muted: u32,
    pub line: u32,
    pub accent: u32,
    pub accent_soft: u32,
    pub green: u32,
    pub green_soft: u32,
    pub amber: u32,
    pub amber_soft: u32,
    pub red: u32,
    pub red_soft: u32,
    pub overlay: u32,
}

const LIGHT: Palette = Palette {
    background: 0xe5e9ef,
    sidebar: 0xdce0e8,
    surface: 0xeff1f5,
    surface_muted: 0xdce0e8,
    ink: 0x4c4f69,
    muted: 0x7c7f93,
    line: 0xccd0da,
    accent: 0x7287fd,
    accent_soft: 0xdde2f6,
    green: 0x5aa93b,
    green_soft: 0xe1eadc,
    amber: 0xdf8e1d,
    amber_soft: 0xede3d7,
    red: 0xd26a53,
    red_soft: 0xf2d9d4,
    overlay: 0x15211b66,
};

const DARK: Palette = Palette {
    background: 0x181825,
    sidebar: 0x11111b,
    surface: 0x1e1e2e,
    surface_muted: 0x302d41,
    ink: 0xcdd6f4,
    muted: 0x9399b2,
    line: 0x313244,
    accent: 0xb4befe,
    accent_soft: 0x33344b,
    green: 0xa6e3a1,
    green_soft: 0x364143,
    amber: 0xf9e2af,
    amber_soft: 0x3d3940,
    red: 0xf38ba8,
    red_soft: 0x443244,
    overlay: 0x11111bb3,
};

impl Palette {
    pub fn current(cx: &App) -> Self {
        if cx.theme().is_dark() { DARK } else { LIGHT }
    }
}

pub fn configure_theme(cx: &mut App) {
    ThemeRegistry::global_mut(cx)
        .load_themes_from_str(CATPPUCCIN_THEMES)
        .expect("embedded Catppuccin themes must be valid");
    let registry = ThemeRegistry::global(cx);
    let latte = registry
        .themes()
        .get("Catppuccin Latte")
        .cloned()
        .expect("embedded Catppuccin Latte theme must be registered");
    let mocha = registry
        .themes()
        .get("Catppuccin Mocha")
        .cloned()
        .expect("embedded Catppuccin Mocha theme must be registered");
    let theme = Theme::global_mut(cx);
    theme.light_theme = latte;
    theme.dark_theme = mocha;
    theme.font_size = px(14.);
    theme.radius = px(8.);
    theme.radius_lg = px(14.);
    // No window exists yet; each window re-reads the system appearance when it opens.
    Theme::change(theme_mode(appearance(cx), None, cx), None, cx);
}

pub fn appearance(cx: &App) -> Appearance {
    preferences::settings(cx).appearance
}

/// Switches every window to `appearance` and saves it for the next launch.
pub fn set_appearance(appearance: Appearance, window: &Window, cx: &mut App) -> Result<(), String> {
    let saved = preferences::update(cx, |settings| settings.appearance = appearance);
    sync_appearance(window, cx);
    saved
}

/// Applies the preferred appearance to a new window and keeps following the
/// system appearance while the window is open.
pub fn follow_appearance(window: &mut Window, cx: &mut App) {
    sync_appearance(window, cx);
    window
        .observe_window_appearance(|window, cx| sync_appearance(window, cx))
        .detach();
}

fn sync_appearance(window: &Window, cx: &mut App) {
    let mode = theme_mode(appearance(cx), Some(window), cx);
    if cx.theme().mode != mode {
        Theme::change(mode, None, cx);
    }
}

fn theme_mode(appearance: Appearance, window: Option<&Window>, cx: &App) -> ThemeMode {
    match appearance {
        Appearance::System => window
            .map_or_else(|| cx.window_appearance(), Window::appearance)
            .into(),
        Appearance::Light => ThemeMode::Light,
        Appearance::Dark => ThemeMode::Dark,
    }
}

#[cfg(test)]
mod tests {
    use gpui_kit::component::{ThemeMode, ThemeSet};

    use super::{CATPPUCCIN_THEMES, DARK, LIGHT};

    #[test]
    fn embeds_a_light_and_a_dark_catppuccin_flavor() {
        let themes: ThemeSet = serde_json::from_str(CATPPUCCIN_THEMES).unwrap();
        let flavors: Vec<_> = themes
            .themes
            .iter()
            .map(|theme| (theme.name.to_string(), theme.mode))
            .collect();

        assert_eq!(
            flavors,
            [
                ("Catppuccin Latte".to_string(), ThemeMode::Light),
                ("Catppuccin Mocha".to_string(), ThemeMode::Dark),
            ]
        );
    }

    #[test]
    fn palettes_share_colors_with_their_flavor() {
        let themes: serde_json::Value = serde_json::from_str(CATPPUCCIN_THEMES).unwrap();
        for (theme, palette) in themes["themes"]
            .as_array()
            .unwrap()
            .iter()
            .zip([LIGHT, DARK])
        {
            let color = |key: &str| {
                let value = theme["colors"][key].as_str().unwrap();
                u32::from_str_radix(value.trim_start_matches('#'), 16).unwrap()
            };
            assert_eq!(color("background"), palette.background);
            assert_eq!(color("foreground"), palette.ink);
            assert_eq!(color("border"), palette.line);
            assert_eq!(color("muted.background"), palette.surface_muted);
            assert_eq!(color("base.green"), palette.green);
            assert_eq!(color("base.yellow"), palette.amber);
            assert_eq!(color("base.red"), palette.red);
            assert_eq!(color("primary.background"), palette.accent);
        }
    }

    #[test]
    fn each_flavor_uses_a_single_accent() {
        let themes: serde_json::Value = serde_json::from_str(CATPPUCCIN_THEMES).unwrap();
        for theme in themes["themes"].as_array().unwrap() {
            let colors = &theme["colors"];
            for key in ["ring", "primary.active.background", "list.active.border"] {
                assert_eq!(
                    colors[key], colors["primary.background"],
                    "{} {key}",
                    theme["name"]
                );
            }
        }
    }
}
