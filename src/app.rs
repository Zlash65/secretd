use std::{
    collections::{HashMap, HashSet},
    error::Error,
    sync::{Arc, Mutex, mpsc::Sender},
    time::{Duration, Instant},
};

use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Sizable as _, StyledExt as _, Theme, ThemeRegistry,
    TitleBar,
    button::{Button, ButtonVariants as _},
    group_box::{GroupBox, GroupBoxVariants as _},
    h_flex,
    input::{Input, InputEvent, InputState, Textarea, TextareaState},
    menu::{DropdownMenu as _, PopupMenuItem},
    radio::Radio,
    scroll::ScrollableElement as _,
    tab::{Tab, TabBar},
    v_flex,
};
use gpui_kit::{
    App, AppContext, Context, Entity, Focusable as _, Global, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, SharedString, Styled, Subscription, Window, div,
    prelude::FluentBuilder as _, px, rgb,
};
use tray_icon::{
    TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use zeroize::Zeroizing;

use secretd::{
    aws::{AwsAccessLevel, AwsConfiguration, AwsLoginStatus, AwsTarget},
    controller::{
        AppSnapshot, ApprovalDecision, AuditAction, Controller, PendingAwsCredentialRequest,
        PendingRequest,
    },
    grants::DEFAULT_GRANT_SECONDS,
    ipc::{RequestServer, begin_aws_login},
    paths::{default_runtime_path, default_vault_path},
    process::{ProcessIdentity, is_launchd_process, same_process},
};

use crate::icon::{TrayStatus, tray_icon};

const BACKGROUND: u32 = 0xe5e9ef;
const SURFACE: u32 = 0xeff1f5;
const SURFACE_MUTED: u32 = 0xdce0e8;
const INK: u32 = 0x4c4f69;
const MUTED: u32 = 0x7c7f93;
const LINE: u32 = 0xccd0da;
const GREEN: u32 = 0x5aa93b;
const GREEN_SOFT: u32 = 0xe1eadc;
const AMBER: u32 = 0xdf8e1d;
const RED: u32 = 0xd26a53;
const RED_SOFT: u32 = 0xf2d9d4;

const CATPPUCCIN_LATTE_THEME: &str = r##"
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
    }
  ]
}
"##;

#[derive(Clone, Copy, Debug)]
pub enum AppEvent {
    Show,
    Toggle,
    Lock,
    StateChanged,
    Quit,
}

pub struct AppState {
    controller: Arc<Mutex<Controller>>,
    notify: Arc<dyn Fn() + Send + Sync>,
    _request_server: RequestServer,
    tray: TrayIcon,
    tray_menu: Menu,
    tray_status: Mutex<TrayStatus>,
}

impl Global for AppState {}

impl AppState {
    pub fn new(sender: Sender<AppEvent>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let controller = Arc::new(Mutex::new(Controller::new(
            default_vault_path().map_err(std::io::Error::other)?,
        )));
        let notify_sender = sender.clone();
        let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let _ = notify_sender.send(AppEvent::StateChanged);
        });
        let request_server = RequestServer::start(
            Arc::clone(&controller),
            default_runtime_path().map_err(std::io::Error::other)?,
            Arc::clone(&notify),
        )
        .map_err(std::io::Error::other)?;
        let snapshot = controller
            .lock()
            .map_err(|_| std::io::Error::other("secretd state is unavailable"))?
            .snapshot();
        let tray_menu = Menu::new();
        rebuild_tray_menu(&tray_menu, &snapshot)?;
        let tray_status = tray_status(&snapshot);
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu.clone()))
            .with_icon(tray_icon(tray_status).map_err(std::io::Error::other)?)
            .with_tooltip("secretd")
            .with_menu_on_left_click(false)
            .build()?;

        let menu_sender = sender.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let event = match event.id.as_ref() {
                "show" => Some(AppEvent::Show),
                "lock" => Some(AppEvent::Lock),
                "quit" => Some(AppEvent::Quit),
                _ => None,
            };
            if let Some(event) = event {
                let _ = menu_sender.send(event);
            }
        }));
        TrayIconEvent::set_event_handler(Some(move |event| {
            if let TrayIconEvent::Click {
                button,
                button_state,
                ..
            } = event
                && should_toggle_for_tray_click(button, button_state)
            {
                let _ = sender.send(AppEvent::Toggle);
            }
        }));

        Ok(Self {
            controller,
            notify,
            _request_server: request_server,
            tray,
            tray_menu,
            tray_status: Mutex::new(tray_status),
        })
    }

    pub fn controller(&self) -> Arc<Mutex<Controller>> {
        Arc::clone(&self.controller)
    }

    pub fn notify(&self) -> Arc<dyn Fn() + Send + Sync> {
        Arc::clone(&self.notify)
    }

    pub fn snapshot(&self) -> AppSnapshot {
        self.controller
            .lock()
            .expect("secretd controller mutex was poisoned")
            .snapshot()
    }

    pub fn lock(&self) {
        if let Ok(mut controller) = self.controller.lock() {
            controller.lock();
        }
        (self.notify)();
    }

    pub fn refresh_tray(&self) {
        let snapshot = self.snapshot();
        let status = tray_status(&snapshot);
        if let Ok(mut current) = self.tray_status.lock()
            && *current != status
        {
            if let Ok(icon) = tray_icon(status) {
                let _ = self.tray.set_icon(Some(icon));
            }
            *current = status;
        }
        let pending_count = snapshot.pending.len() + snapshot.pending_aws.len();
        let tooltip = if pending_count > 0 {
            format!(
                "secretd — {pending_count} request{} pending",
                if pending_count == 1 { "" } else { "s" }
            )
        } else if snapshot.unlocked {
            format!(
                "secretd — unlocked · {} credentials",
                snapshot.secrets.len()
            )
        } else {
            "secretd — locked".into()
        };
        let _ = self.tray.set_tooltip(Some(tooltip));
        let _ = rebuild_tray_menu(&self.tray_menu, &snapshot);
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        if let Ok(mut controller) = self.controller.lock() {
            controller.lock();
        }
        MenuEvent::set_event_handler::<fn(MenuEvent)>(None);
        TrayIconEvent::set_event_handler::<fn(TrayIconEvent)>(None);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum View {
    #[default]
    Secrets,
    Aws,
    Grants,
    Activity,
}

#[derive(Clone, Debug)]
enum Modal {
    Secret { original_name: Option<String> },
    Password,
    AwsConnection,
    AwsAliases,
    Delete(String),
}

struct AwsAliasInputs {
    account_id: String,
    account_name: String,
    email_address: String,
    roles: Vec<String>,
    profile: Entity<InputState>,
    read_only_role: Entity<InputState>,
    admin_role: Entity<InputState>,
    region: String,
}

struct Toast {
    message: String,
    danger: bool,
    expires_at: Instant,
}

pub struct MainView {
    view: View,
    last_grant_process_check: Option<Instant>,
    auth_password: Entity<InputState>,
    auth_confirmation: Entity<InputState>,
    search: Entity<InputState>,
    secret_name: Entity<InputState>,
    secret_value: Entity<TextareaState>,
    new_password: Entity<InputState>,
    password_confirmation: Entity<InputState>,
    aws_start_url: Entity<InputState>,
    aws_region: Entity<InputState>,
    aws_aliases: Vec<AwsAliasInputs>,
    modal: Option<Modal>,
    auth_error: Option<String>,
    form_error: Option<String>,
    revealed: Option<(String, Zeroizing<String>)>,
    toast: Option<Toast>,
    _subscriptions: Vec<Subscription>,
}

impl MainView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let auth_password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Enter your master password")
                .masked(true)
        });
        let auth_confirmation = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Enter it again")
                .masked(true)
        });
        if !Self::snapshot(cx).unlocked {
            let focus_handle = auth_password.focus_handle(cx);
            window.defer(cx, move |window, cx| {
                focus_handle.focus(window, cx);
            });
        }
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Search credentials…"));
        let _subscriptions = vec![
            cx.subscribe_in(&search, window, |_, _, event, _, cx| {
                if matches!(event, InputEvent::Change) {
                    cx.notify();
                }
            }),
            cx.subscribe_in(&auth_password, window, |this, _, event, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    if Self::snapshot(cx).vault_exists {
                        this.submit_auth_form(window, cx);
                    } else {
                        this.auth_confirmation.update(cx, |input, cx| {
                            input.focus(window, cx);
                        });
                    }
                }
            }),
            cx.subscribe_in(&auth_confirmation, window, |this, _, event, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.submit_auth_form(window, cx);
                }
            }),
        ];
        Self {
            view: View::Secrets,
            last_grant_process_check: None,
            auth_password,
            auth_confirmation,
            search,
            secret_name: cx
                .new(|cx| InputState::new(window, cx).placeholder("service/account/token")),
            secret_value: cx.new(|cx| TextareaState::new(window, cx).placeholder("Secret value")),
            new_password: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Enter a new password")
                    .masked(true)
            }),
            password_confirmation: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Enter it again")
                    .masked(true)
            }),
            aws_start_url: cx.new(|cx| {
                InputState::new(window, cx).placeholder("https://example.awsapps.com/start")
            }),
            aws_region: cx.new(|cx| InputState::new(window, cx).placeholder("ca-central-1")),
            aws_aliases: Vec::new(),
            modal: None,
            auth_error: None,
            form_error: None,
            revealed: None,
            toast: None,
            _subscriptions,
        }
    }

    fn controller(cx: &App) -> Arc<Mutex<Controller>> {
        cx.global::<AppState>().controller()
    }

    fn snapshot(cx: &App) -> AppSnapshot {
        cx.global::<AppState>().snapshot()
    }

    fn signal(cx: &App) {
        (cx.global::<AppState>().notify())();
    }

    fn input_value(input: &Entity<InputState>, cx: &App) -> String {
        input.read(cx).value().to_string()
    }

    fn set_input(
        input: &Entity<InputState>,
        value: impl Into<SharedString>,
        window: &mut Window,
        cx: &mut App,
    ) {
        let value: SharedString = value.into();
        input.update(cx, |input, cx| input.set_value(value, window, cx));
    }

    pub fn clear_sensitive(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for input in [
            &self.auth_password,
            &self.auth_confirmation,
            &self.secret_name,
            &self.new_password,
            &self.password_confirmation,
        ] {
            Self::set_input(input, "", window, cx);
        }
        self.secret_value
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.aws_aliases.clear();
        self.modal = None;
        self.revealed = None;
        self.form_error = None;
        self.auth_error = None;
        cx.notify();
    }

    fn lock_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.clear_sensitive(window, cx);
        cx.global::<AppState>().lock();
    }

    fn toast(&mut self, message: impl Into<String>, danger: bool, cx: &mut Context<Self>) {
        self.toast = Some(Toast {
            message: message.into(),
            danger,
            expires_at: Instant::now() + Duration::from_millis(2_800),
        });
        cx.notify();
    }

    fn submit_auth(
        &mut self,
        _: &gpui_kit::ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.submit_auth_form(window, cx);
    }

    fn submit_auth_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let snapshot = Self::snapshot(cx);
        let creating = !snapshot.vault_exists;
        let password = Zeroizing::new(Self::input_value(&self.auth_password, cx));
        let confirmation = Zeroizing::new(Self::input_value(&self.auth_confirmation, cx));
        self.auth_error = None;
        if creating && *password != *confirmation {
            self.auth_error = Some("Passwords do not match".into());
            cx.notify();
            return;
        }
        let result = Self::controller(cx)
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                if creating {
                    controller.create_vault(&password)
                } else {
                    controller.unlock(&password)
                }
                .map_err(|error| error.to_string())
            });
        match result {
            Ok(()) => {
                Self::set_input(&self.auth_password, "", window, cx);
                Self::set_input(&self.auth_confirmation, "", window, cx);
                Self::signal(cx);
            }
            Err(error) => self.auth_error = Some(error),
        }
        cx.notify();
    }

    fn switch_view(&mut self, view: View, cx: &mut Context<Self>) {
        if view == View::Grants && self.view != View::Grants {
            self.last_grant_process_check = None;
        }
        self.view = view;
        cx.notify();
    }

    fn refresh_grant_liveness(&mut self, cx: &App) {
        if self.view != View::Grants {
            return;
        }
        let now = Instant::now();
        if self
            .last_grant_process_check
            .is_some_and(|last| now.duration_since(last) < Duration::from_secs(1))
        {
            return;
        }
        if let Ok(mut controller) = Self::controller(cx).lock() {
            controller.prune_exited_aws_grants();
        }
        self.last_grant_process_check = Some(now);
    }

    pub fn show_aws_login(&mut self, cx: &mut Context<Self>) {
        self.switch_view(View::Aws, cx);
    }

    fn open_secret(
        &mut self,
        original_name: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let (name, value) = if let Some(name) = original_name.as_ref() {
            match Self::controller(cx)
                .lock()
                .map_err(|_| "secretd state is unavailable".to_string())
                .and_then(|controller| {
                    controller
                        .reveal_secret(name)
                        .map_err(|error| error.to_string())
                }) {
                Ok(value) => (name.clone(), value.to_string()),
                Err(error) => {
                    self.toast(error, true, cx);
                    return;
                }
            }
        } else {
            (String::new(), String::new())
        };
        Self::set_input(&self.secret_name, name, window, cx);
        self.secret_value
            .update(cx, |input, cx| input.set_value(value, window, cx));
        self.form_error = None;
        self.modal = Some(Modal::Secret { original_name });
        cx.notify();
    }

    fn save_secret(
        &mut self,
        _: &gpui_kit::ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(Modal::Secret { original_name }) = self.modal.clone() else {
            return;
        };
        let name = Self::input_value(&self.secret_name, cx);
        let value = Zeroizing::new(self.secret_value.read(cx).value().to_string());
        let result = Self::controller(cx)
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                controller
                    .save_secret(&name, &value, original_name.as_deref())
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(()) => {
                Self::set_input(&self.secret_name, "", window, cx);
                self.secret_value
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.modal = None;
                self.revealed = None;
                self.form_error = None;
                self.toast("Saved securely", false, cx);
                Self::signal(cx);
            }
            Err(error) => self.form_error = Some(error),
        }
        cx.notify();
    }

    fn reveal_secret(&mut self, name: String, cx: &mut Context<Self>) {
        if self
            .revealed
            .as_ref()
            .is_some_and(|(revealed, _)| revealed == &name)
        {
            self.revealed = None;
        } else {
            match Self::controller(cx)
                .lock()
                .map_err(|_| "secretd state is unavailable".to_string())
                .and_then(|controller| {
                    controller
                        .reveal_secret(&name)
                        .map_err(|error| error.to_string())
                }) {
                Ok(value) => self.revealed = Some((name, value)),
                Err(error) => self.toast(error, true, cx),
            }
        }
        cx.notify();
    }

    fn delete_secret(&mut self, name: String, cx: &mut Context<Self>) {
        let result = Self::controller(cx)
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                controller
                    .delete_secret(&name)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(()) => {
                self.modal = None;
                self.revealed = None;
                self.toast("Credential deleted", false, cx);
                Self::signal(cx);
            }
            Err(error) => self.toast(error, true, cx),
        }
        cx.notify();
    }

    fn open_password(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        Self::set_input(&self.new_password, "", window, cx);
        Self::set_input(&self.password_confirmation, "", window, cx);
        self.form_error = None;
        self.modal = Some(Modal::Password);
        cx.notify();
    }

    fn save_password(
        &mut self,
        _: &gpui_kit::ClickEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let password = Zeroizing::new(Self::input_value(&self.new_password, cx));
        let confirmation = Zeroizing::new(Self::input_value(&self.password_confirmation, cx));
        if *password != *confirmation {
            self.form_error = Some("Passwords do not match".into());
            cx.notify();
            return;
        }
        let result = Self::controller(cx)
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                controller
                    .change_password(&password)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(()) => {
                Self::set_input(&self.new_password, "", window, cx);
                Self::set_input(&self.password_confirmation, "", window, cx);
                self.modal = None;
                self.form_error = None;
                self.toast("Password changed", false, cx);
            }
            Err(error) => self.form_error = Some(error),
        }
        cx.notify();
    }

    fn open_aws_connection(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let snapshot = Self::snapshot(cx);
        let connection = snapshot.aws.as_ref().map(|aws| &aws.configuration);
        Self::set_input(
            &self.aws_start_url,
            connection.map_or("", |value| value.start_url.as_str()),
            window,
            cx,
        );
        Self::set_input(
            &self.aws_region,
            connection.map_or("", |value| value.sso_region.as_str()),
            window,
            cx,
        );
        self.form_error = None;
        self.modal = Some(Modal::AwsConnection);
        cx.notify();
    }

    fn save_aws_connection(
        &mut self,
        _: &gpui_kit::ClickEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let start_url = Self::input_value(&self.aws_start_url, cx);
        let region = Self::input_value(&self.aws_region, cx);
        let result = Self::controller(cx)
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                controller
                    .save_aws_connection(start_url.trim().to_string(), region.trim().to_string())
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(()) => {
                self.modal = None;
                self.form_error = None;
                match begin_aws_login(Self::controller(cx), cx.global::<AppState>().notify()) {
                    Ok(()) => self.toast("AWS connection saved; sign in to continue", false, cx),
                    Err(error) => self.toast(error, true, cx),
                }
                Self::signal(cx);
            }
            Err(error) => self.form_error = Some(error),
        }
        cx.notify();
    }

    fn begin_aws_refresh(&mut self, cx: &mut Context<Self>) {
        match begin_aws_login(Self::controller(cx), cx.global::<AppState>().notify()) {
            Ok(()) => self.toast("Refreshing AWS session and accounts", false, cx),
            Err(error) => self.toast(error, true, cx),
        }
    }

    fn open_aws_aliases(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let snapshot = Self::snapshot(cx);
        let Some(aws) = snapshot.aws else {
            return;
        };
        let mut used_aliases = HashSet::new();
        self.aws_aliases = aws
            .discovered_accounts
            .iter()
            .map(|account| {
                let existing = aws
                    .configuration
                    .targets
                    .iter()
                    .find(|target| target.account_id == account.account_id);
                let mut profile = existing.map_or_else(
                    || suggested_alias(&account.account_name, &account.account_id),
                    |target| target.profile.clone(),
                );
                if !used_aliases.insert(profile.clone()) {
                    profile = format!("{}-{}", profile, &account.account_id[8..]);
                    used_aliases.insert(profile.clone());
                }
                let read_only = existing.map_or_else(
                    || suggested_role(&account.roles, AwsAccessLevel::ReadOnly),
                    |target| target.read_only_role.clone(),
                );
                let admin = existing.map_or_else(
                    || suggested_role(&account.roles, AwsAccessLevel::Admin),
                    |target| target.admin_role.clone(),
                );
                AwsAliasInputs {
                    account_id: account.account_id.clone(),
                    account_name: account.account_name.clone(),
                    email_address: account.email_address.clone(),
                    roles: account.roles.clone(),
                    profile: cx.new(|cx| InputState::new(window, cx).default_value(profile)),
                    read_only_role: cx
                        .new(|cx| InputState::new(window, cx).default_value(read_only)),
                    admin_role: cx.new(|cx| InputState::new(window, cx).default_value(admin)),
                    region: existing.map_or_else(String::new, |target| target.region.clone()),
                }
            })
            .collect();
        self.form_error = None;
        self.modal = Some(Modal::AwsAliases);
        cx.notify();
    }

    fn save_aws_aliases(
        &mut self,
        _: &gpui_kit::ClickEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let snapshot = Self::snapshot(cx);
        let Some(aws) = snapshot.aws else {
            self.form_error = Some("AWS connection is no longer available".into());
            cx.notify();
            return;
        };
        let mut targets = Vec::new();
        for input in &self.aws_aliases {
            let profile = Self::input_value(&input.profile, cx).trim().to_string();
            if profile.is_empty() {
                continue;
            }
            let read_only_role = Self::input_value(&input.read_only_role, cx);
            let admin_role = Self::input_value(&input.admin_role, cx);
            if !input.roles.contains(&read_only_role) {
                self.form_error = Some(format!("Select a read-only role for '{profile}'"));
                cx.notify();
                return;
            }
            if !input.roles.contains(&admin_role) {
                self.form_error = Some(format!("Select an admin role for '{profile}'"));
                cx.notify();
                return;
            }
            targets.push(AwsTarget {
                profile,
                account_id: input.account_id.clone(),
                read_only_role,
                admin_role,
                region: input.region.clone(),
            });
        }
        if targets.is_empty() {
            self.form_error = Some("Assign an alias to at least one AWS account".into());
            cx.notify();
            return;
        }
        let result = Self::controller(cx)
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                controller
                    .save_aws_configuration(AwsConfiguration {
                        start_url: aws.configuration.start_url,
                        sso_region: aws.configuration.sso_region,
                        targets,
                    })
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(()) => {
                self.aws_aliases.clear();
                self.modal = None;
                self.form_error = None;
                self.toast("AWS profile aliases saved", false, cx);
                Self::signal(cx);
            }
            Err(error) => self.form_error = Some(error),
        }
        cx.notify();
    }

    fn close_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if matches!(self.modal, Some(Modal::Secret { .. })) {
            Self::set_input(&self.secret_name, "", window, cx);
            self.secret_value
                .update(cx, |input, cx| input.set_value("", window, cx));
        }
        if matches!(self.modal, Some(Modal::Password)) {
            Self::set_input(&self.new_password, "", window, cx);
            Self::set_input(&self.password_confirmation, "", window, cx);
        }
        self.aws_aliases.clear();
        self.modal = None;
        self.form_error = None;
        cx.notify();
    }

    fn render_auth(&self, creating: bool, cx: &mut Context<Self>) -> gpui_kit::AnyElement {
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .bg(rgb(BACKGROUND))
            .child(
                v_flex()
                    .w(px(460.))
                    .gap_4()
                    .p_8()
                    .bg(rgb(SURFACE))
                    .border_1()
                    .border_color(rgb(LINE))
                    .rounded(px(20.))
                    .child(brand())
                    .child(
                        v_flex()
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(26.))
                                    .font_semibold()
                                    .text_color(rgb(INK))
                                    .child(if creating {
                                        "Create your vault"
                                    } else {
                                        "Welcome back"
                                    }),
                            )
                            .child(div().text_color(rgb(MUTED)).child(if creating {
                                "Protect credentials in an encrypted vault that stays on this Mac."
                            } else {
                                "Unlock your vault to manage credentials and approve access."
                            })),
                    )
                    .child(field(
                        "Master password",
                        Input::new(&self.auth_password).mask_toggle(),
                    ))
                    .when(creating, |this| {
                        this.child(field(
                            "Confirm password",
                            Input::new(&self.auth_confirmation).mask_toggle(),
                        ))
                    })
                    .when_some(self.auth_error.clone(), |this, error| {
                        this.child(error_banner(error))
                    })
                    .child(
                        Button::new("submit-auth")
                            .primary()
                            .large()
                            .w_full()
                            .label(if creating {
                                "Create encrypted vault"
                            } else {
                                "Unlock vault"
                            })
                            .on_click(cx.listener(Self::submit_auth)),
                    )
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(MUTED))
                            .text_center()
                            .child("AES-256 encrypted • PBKDF2 protected"),
                    ),
            )
            .into_any_element()
    }

    fn render_header(
        &self,
        snapshot: &AppSnapshot,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let entity = cx.entity();
        let active_count =
            snapshot.grants.len() + snapshot.aws_grants.len() + snapshot.aws_denials.len();
        let activity_count = snapshot.audit.len();
        let badge_color = cx.theme().muted_foreground;
        let selected_index = match self.view {
            View::Secrets => 0,
            View::Aws => 1,
            View::Grants => 2,
            View::Activity => 3,
        };
        TitleBar::new()
            .child(
                h_flex()
                    .w_full()
                    .h_full()
                    .pr_3()
                    .gap_3()
                    .items_center()
                    .child(title_bar_brand())
                    .child(status_pill("Vault unlocked", GREEN, GREEN_SOFT))
                    .child(div().w(px(4.)))
                    .child(
                        TabBar::new("main-navigation")
                            .segmented()
                            .small()
                            .selected_index(selected_index)
                            .on_click(move |index, _, cx| {
                                let view = match index {
                                    0 => View::Secrets,
                                    1 => View::Aws,
                                    2 => View::Grants,
                                    _ => View::Activity,
                                };
                                entity.update(cx, |this, cx| this.switch_view(view, cx));
                            })
                            .child(Tab::new().label("Credentials"))
                            .child(Tab::new().label("AWS SSO"))
                            .child(counted_tab("Grants", active_count, badge_color))
                            .child(counted_tab("Activity", activity_count, badge_color)),
                    )
                    .child(div().flex_1())
                    .child(
                        Button::new("change-password")
                            .ghost()
                            .small()
                            .label("Password")
                            .on_click(
                                cx.listener(|this, _, window, cx| this.open_password(window, cx)),
                            ),
                    )
                    .child(
                        Button::new("lock")
                            .outline()
                            .small()
                            .label("Lock")
                            .on_click(
                                cx.listener(|this, _, window, cx| this.lock_vault(window, cx)),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_secrets(
        &self,
        snapshot: &AppSnapshot,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let query = Self::input_value(&self.search, cx).to_ascii_lowercase();
        let visible: Vec<_> = snapshot
            .secrets
            .iter()
            .filter(|secret| query.is_empty() || secret.name.to_ascii_lowercase().contains(&query))
            .cloned()
            .collect();
        let entity = cx.entity();
        v_flex()
            .gap_4()
            .child(section_header(
                "Credentials",
                "Manage encrypted credentials stored in your local vault.",
            ))
            .child(
                h_flex()
                    .gap_3()
                    .child(div().w(px(320.)).child(Input::new(&self.search)))
                    .child(div().flex_1())
                    .child(
                        Button::new("new-secret")
                            .primary()
                            .label("+ New credential")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.open_secret(None, window, cx)
                            })),
                    ),
            )
            .when(visible.is_empty(), |this| {
                this.child(empty_state(if snapshot.secrets.is_empty() {
                    "Your vault is empty"
                } else {
                    "No matching credentials"
                }))
            })
            .children(visible.into_iter().map(|secret| {
                let name = secret.name.clone();
                let reveal_name = name.clone();
                let edit_name = name.clone();
                let delete_name = name.clone();
                let revealed = self
                    .revealed
                    .as_ref()
                    .filter(|(revealed, _)| revealed == &name)
                    .map(|(_, value)| value.to_string());
                card()
                    .gap_3()
                    .child(
                        h_flex()
                            .gap_3()
                            .items_center()
                            .child(credential_mark())
                            .child(div().font_semibold().text_color(rgb(INK)).child(name))
                            .child(div().flex_1())
                            .child(
                                Button::new(SharedString::from(format!("reveal-{reveal_name}")))
                                    .outline()
                                    .label(if revealed.is_some() { "Hide" } else { "Reveal" })
                                    .on_click({
                                        let entity = entity.clone();
                                        move |_, _, cx| {
                                            entity.update(cx, |this, cx| {
                                                this.reveal_secret(reveal_name.clone(), cx)
                                            });
                                        }
                                    }),
                            )
                            .child(
                                Button::new(SharedString::from(format!("edit-{edit_name}")))
                                    .outline()
                                    .label("Edit")
                                    .on_click({
                                        let entity = entity.clone();
                                        move |_, window, cx| {
                                            entity.update(cx, |this, cx| {
                                                this.open_secret(
                                                    Some(edit_name.clone()),
                                                    window,
                                                    cx,
                                                )
                                            });
                                        }
                                    }),
                            )
                            .child(
                                Button::new(SharedString::from(format!("delete-{delete_name}")))
                                    .danger()
                                    .ghost()
                                    .label("Delete")
                                    .on_click({
                                        let entity = entity.clone();
                                        move |_, _, cx| {
                                            entity.update(cx, |this, cx| {
                                                this.modal =
                                                    Some(Modal::Delete(delete_name.clone()));
                                                cx.notify();
                                            });
                                        }
                                    }),
                            ),
                    )
                    .when_some(revealed, |this, value| {
                        this.child(
                            v_flex()
                                .gap_1()
                                .pt_2()
                                .border_t_1()
                                .border_color(rgb(LINE))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .font_semibold()
                                        .text_color(rgb(MUTED))
                                        .child("SECRET VALUE"),
                                )
                                .child(
                                    div()
                                        .p_3()
                                        .bg(rgb(SURFACE_MUTED))
                                        .rounded(px(8.))
                                        .font_family("monospace")
                                        .child(value),
                                ),
                        )
                    })
            }))
            .into_any_element()
    }

    fn render_aws(&self, snapshot: &AppSnapshot, cx: &mut Context<Self>) -> gpui_kit::AnyElement {
        let login_in_progress = matches!(
            snapshot.aws_login,
            AwsLoginStatus::Starting
                | AwsLoginStatus::AwaitingUser(_)
                | AwsLoginStatus::Discovering
        );
        let has_connection = snapshot.aws.is_some();
        let has_discovered_accounts = snapshot
            .aws
            .as_ref()
            .is_some_and(|aws| !aws.discovered_accounts.is_empty());
        let entity = cx.entity();
        let configure_entity = entity.clone();
        let actions = h_flex()
            .gap_2()
            .when(has_connection, |this| {
                this.child(
                    Button::new("refresh-aws")
                        .primary()
                        .small()
                        .label(if login_in_progress {
                            "Working…"
                        } else {
                            "Refresh"
                        })
                        .disabled(login_in_progress)
                        .on_click(cx.listener(|this, _, _, cx| this.begin_aws_refresh(cx))),
                )
                .child(
                    Button::new("configure-aws")
                        .outline()
                        .small()
                        .label("Configure")
                        .disabled(login_in_progress)
                        .dropdown_menu(move |menu, _, _| {
                            let aliases_entity = configure_entity.clone();
                            let connection_entity = configure_entity.clone();
                            menu.when(has_discovered_accounts, |this| {
                                this.item(PopupMenuItem::new("Profile aliases").on_click(
                                    move |_, window, cx| {
                                        aliases_entity.update(cx, |this, cx| {
                                            this.open_aws_aliases(window, cx)
                                        });
                                    },
                                ))
                            })
                            .item(
                                PopupMenuItem::new("SSO connection").on_click(
                                    move |_, window, cx| {
                                        connection_entity.update(cx, |this, cx| {
                                            this.open_aws_connection(window, cx)
                                        });
                                    },
                                ),
                            )
                        }),
                )
            })
            .when(!has_connection, |this| {
                this.child(
                    Button::new("edit-aws-connection")
                        .primary()
                        .small()
                        .label("Connect AWS")
                        .on_click(
                            cx.listener(|this, _, window, cx| this.open_aws_connection(window, cx)),
                        ),
                )
            });
        let mut content = v_flex().gap_4().child(
            h_flex()
                .items_start()
                .child(section_header(
                    "AWS profiles",
                    "IAM Identity Center accounts and role mappings.",
                ))
                .child(div().flex_1())
                .child(actions),
        );
        content = match &snapshot.aws_login {
            AwsLoginStatus::Starting => {
                content.child(status_pill("Checking AWS session…", AMBER, SURFACE_MUTED))
            }
            AwsLoginStatus::AwaitingUser(authorization) => {
                let url = authorization.url.clone();
                content.child(
                    card()
                        .bg(rgb(GREEN_SOFT))
                        .child(
                            div()
                                .font_semibold()
                                .child("Complete sign-in in your browser"),
                        )
                        .child(
                            div().child("Sign in or approve access in the browser on this computer. secretd will continue automatically."),
                        )
                        .child(
                            Button::new("open-aws-login")
                                .primary()
                                .label("Open AWS sign-in")
                                .on_click(move |_, _, cx| cx.open_url(&url)),
                        )
                        .child(div().text_color(rgb(MUTED)).child(format!(
                            "This request expires in {}",
                            duration_until_seconds(authorization.expires_at)
                        ))),
                )
            }
            AwsLoginStatus::Discovering => content.child(status_pill(
                "Loading AWS accounts and roles…",
                AMBER,
                SURFACE_MUTED,
            )),
            AwsLoginStatus::LoggedIn { expires_at } => content.child(status_pill(
                &format!(
                    "Signed in · token renews automatically ({} remaining)",
                    duration_until_seconds(*expires_at)
                ),
                GREEN,
                GREEN_SOFT,
            )),
            AwsLoginStatus::Failed(error) => content.child(error_banner(error.clone())),
            AwsLoginStatus::Idle => content,
        };
        let Some(aws) = &snapshot.aws else {
            return content
                .child(empty_state(
                    "Step 1 · Enter your AWS access portal URL to begin",
                ))
                .into_any_element();
        };
        content
            .child(
                GroupBox::new()
                    .id("aws-connection")
                    .outline()
                    .title(div().font_semibold().child("SSO connection"))
                    .child(
                        h_flex()
                            .gap_3()
                            .items_center()
                            .child(
                                v_flex()
                                    .min_w_0()
                                    .flex_1()
                                    .gap_1()
                                    .child(
                                        div()
                                            .font_semibold()
                                            .overflow_hidden()
                                            .text_ellipsis()
                                            .whitespace_nowrap()
                                            .child(aws.configuration.start_url.clone()),
                                    )
                                    .child(div().text_size(px(12.)).text_color(rgb(MUTED)).child(
                                        format!("Region · {}", aws.configuration.sso_region),
                                    )),
                            )
                            .child(status_pill(
                                if aws.logged_in {
                                    "Available"
                                } else {
                                    "Sign in"
                                },
                                if aws.logged_in { GREEN } else { AMBER },
                                SURFACE_MUTED,
                            )),
                    ),
            )
            .when(!aws.discovery_complete, |this| {
                this.child(empty_state(
                    "Step 2 · Sign in to discover your AWS accounts",
                ))
            })
            .when(
                aws.discovery_complete && aws.discovered_accounts.is_empty(),
                |this| {
                    this.child(empty_state(
                        "AWS returned no accounts assigned to this identity",
                    ))
                },
            )
            .when(!aws.configuration.targets.is_empty(), |this| {
                this.child(
                    v_flex()
                        .gap_3()
                        .child(
                            div()
                                .text_size(px(18.))
                                .font_semibold()
                                .child("Configured profiles"),
                        )
                        .children(aws.configuration.targets.iter().map(|target| {
                            GroupBox::new()
                                .id(SharedString::from(format!(
                                    "aws-profile-{}",
                                    target.profile
                                )))
                                .outline()
                                .child(
                                    h_flex()
                                        .gap_3()
                                        .items_center()
                                        .child(
                                            div()
                                                .size(px(36.))
                                                .flex_shrink_0()
                                                .rounded(px(10.))
                                                .bg(rgb(SURFACE_MUTED))
                                                .text_color(rgb(INK))
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .text_size(px(11.))
                                                .font_semibold()
                                                .child("AWS"),
                                        )
                                        .child(
                                            v_flex()
                                                .min_w_0()
                                                .flex_1()
                                                .gap_1()
                                                .child(
                                                    div()
                                                        .font_semibold()
                                                        .font_family("monospace")
                                                        .child(target.profile.clone()),
                                                )
                                                .child(
                                                    div()
                                                        .text_size(px(12.))
                                                        .text_color(rgb(MUTED))
                                                        .child(format!(
                                                            "Account {}",
                                                            target.account_id
                                                        )),
                                                ),
                                        )
                                        .child(
                                            v_flex()
                                                .flex_shrink_0()
                                                .items_end()
                                                .gap_1()
                                                .child(
                                                    div()
                                                        .text_size(px(12.))
                                                        .child(target.read_only_role.clone()),
                                                )
                                                .child(
                                                    div()
                                                        .text_size(px(12.))
                                                        .text_color(rgb(MUTED))
                                                        .child(target.admin_role.clone()),
                                                ),
                                        ),
                                )
                        })),
                )
            })
            .when(
                aws.discovery_complete
                    && !aws.discovered_accounts.is_empty()
                    && aws.configuration.targets.is_empty(),
                |this| {
                    this.child(
                        Button::new("assign-aliases")
                            .primary()
                            .label("Assign profile aliases")
                            .on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.open_aws_aliases(window, cx)
                                }),
                            ),
                    )
                },
            )
            .into_any_element()
    }

    fn render_grants(
        &self,
        snapshot: &AppSnapshot,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let entity = cx.entity();
        v_flex()
            .gap_4()
            .child(section_header(
                "Grants",
                "Manage temporary access grants and remembered denials.",
            ))
            .when(!snapshot.aws_grants.is_empty(), |this| {
                this.child(
                    div()
                        .text_color(rgb(MUTED))
                        .text_sm()
                        .child("Access changes apply to future credential requests. Issued AWS credentials remain valid until they expire."),
                )
            })
            .when(
                snapshot.grants.is_empty()
                    && snapshot.aws_grants.is_empty()
                    && snapshot.aws_denials.is_empty(),
                |this| this.child(empty_state("No active grants or blocks")),
            )
            .children(snapshot.aws_grants.iter().map(|grant| {
                let revoke_id = grant.id.clone();
                let extend_id = grant.id.clone();
                let change_id = grant.id.clone();
                let change_entity = entity.clone();
                let (level, label) = match grant.level {
                    AwsAccessLevel::ReadOnly => (AwsAccessLevel::Admin, "Switch to admin"),
                    AwsAccessLevel::Admin => (AwsAccessLevel::ReadOnly, "Switch to read-only"),
                };
                card().child(
                    h_flex()
                        .gap_3()
                        .child(
                            v_flex()
                                .min_w_0()
                                .flex_1()
                                .gap_1()
                                .child(
                                    div()
                                        .font_semibold()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .whitespace_nowrap()
                                        .child(format!(
                                            "AWS {} · {} credentials",
                                            grant.profile,
                                            grant.level.label()
                                        )),
                                )
                                .child(
                                    div()
                                        .text_color(rgb(MUTED))
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .whitespace_nowrap()
                                        .child(format!(
                                            "{} · PID {} · expires in {}",
                                            compact_process_label(&grant.process),
                                            grant.process.pid,
                                            duration_until(grant.expires_at)
                                        )),
                                ),
                        )
                        .child(
                            Button::new(SharedString::from(format!("access-{change_id}")))
                                .flex_shrink_0()
                                .outline()
                                .label(label)
                                .on_click(move |_, _, cx| {
                                    change_entity.update(cx, |this, cx| {
                                        this.set_aws_grant_level(change_id.clone(), level, cx)
                                    });
                                }),
                        )
                        .child(action_button(
                            "Extend",
                            extend_id,
                            true,
                            true,
                            entity.clone(),
                        ))
                        .child(action_button(
                            "Revoke",
                            revoke_id,
                            false,
                            true,
                            entity.clone(),
                        )),
                )
            }))
            .children(snapshot.grants.iter().map(|grant| {
                let revoke_id = grant.id.clone();
                let extend_id = grant.id.clone();
                card().child(
                    h_flex()
                        .gap_3()
                        .child(
                            v_flex()
                                .min_w_0()
                                .flex_1()
                                .gap_1()
                                .child(
                                    div()
                                        .font_semibold()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .whitespace_nowrap()
                                        .child(grant.resource.clone()),
                                )
                                .child(
                                    div()
                                        .text_color(rgb(MUTED))
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .whitespace_nowrap()
                                        .child(format!(
                                            "{} · PID {} · expires in {}",
                                            compact_process_label(&grant.process),
                                            grant.process.pid,
                                            duration_until(grant.expires_at)
                                        )),
                                ),
                        )
                        .child(action_button(
                            "Extend",
                            extend_id,
                            true,
                            false,
                            entity.clone(),
                        ))
                        .child(action_button(
                            "Revoke",
                            revoke_id,
                            false,
                            false,
                            entity.clone(),
                        )),
                )
            }))
            .children(snapshot.aws_denials.iter().map(|denial| {
                let denial_id = denial.id.clone();
                let entity = entity.clone();
                card().child(
                    h_flex()
                        .gap_3()
                        .child(
                            v_flex()
                                .min_w_0()
                                .flex_1()
                                .gap_1()
                                .child(
                                    div()
                                        .font_semibold()
                                        .text_color(rgb(RED))
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .whitespace_nowrap()
                                        .child(format!("Blocked · AWS {}", denial.profile)),
                                )
                                .child(
                                    div()
                                        .text_color(rgb(MUTED))
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .whitespace_nowrap()
                                        .child(format!(
                                            "{} · PID {} · expires in {}",
                                            compact_process_label(&denial.process),
                                            denial.process.pid,
                                            duration_until(denial.expires_at)
                                        )),
                                ),
                        )
                        .child(
                            Button::new(SharedString::from(format!("unblock-{denial_id}")))
                                .flex_shrink_0()
                                .outline()
                                .label("Unblock")
                                .on_click(move |_, _, cx| {
                                    entity.update(cx, |this, cx| {
                                        this.unblock_aws_denial(denial_id.clone(), cx)
                                    });
                                }),
                        ),
                )
            }))
            .into_any_element()
    }

    fn unblock_aws_denial(&mut self, id: String, cx: &mut Context<Self>) {
        if let Ok(mut controller) = Self::controller(cx).lock() {
            controller.revoke_aws_denial(&id);
        }
        Self::signal(cx);
        cx.notify();
    }

    fn set_aws_grant_level(&mut self, id: String, level: AwsAccessLevel, cx: &mut Context<Self>) {
        let result = Self::controller(cx)
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                controller
                    .set_aws_grant_level(&id, level)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(()) => self.toast(
                format!("AWS grant switched to {}", level.label()),
                false,
                cx,
            ),
            Err(error) => self.toast(error, true, cx),
        }
        Self::signal(cx);
        cx.notify();
    }

    fn mutate_grant(&mut self, id: String, extend: bool, aws: bool, cx: &mut Context<Self>) {
        if let Ok(mut controller) = Self::controller(cx).lock() {
            match (extend, aws) {
                (true, true) => controller.extend_aws_grant(&id),
                (false, true) => controller.revoke_aws_grant(&id),
                (true, false) => {
                    controller.extend_grant(&id);
                }
                (false, false) => controller.revoke_grant(&id),
            }
        }
        Self::signal(cx);
        cx.notify();
    }

    fn render_activity(&self, snapshot: &AppSnapshot) -> gpui_kit::AnyElement {
        v_flex()
            .gap_4()
            .child(section_header(
                "Activity",
                "A memory-only record that is cleared when secretd exits.",
            ))
            .when(snapshot.audit.is_empty(), |this| {
                this.child(empty_state("No activity yet"))
            })
            .children(snapshot.audit.iter().map(|entry| {
                card()
                    .gap_2()
                    .child(
                        h_flex()
                            .gap_3()
                            .child(
                                div()
                                    .font_semibold()
                                    .text_color(rgb(match entry.action {
                                        AuditAction::Denied
                                        | AuditAction::TimedOut
                                        | AuditAction::Revoked => RED,
                                        _ => GREEN,
                                    }))
                                    .child(audit_label(entry.action)),
                            )
                            .child(div().font_family("monospace").child(entry.secret.clone()))
                            .child(div().flex_1())
                            .child(
                                div()
                                    .text_color(rgb(MUTED))
                                    .child(duration_since(entry.occurred_at)),
                            ),
                    )
                    .child(div().text_color(rgb(MUTED)).child(format!(
                        "{} · PID {}",
                        compact_process_label(&entry.process),
                        entry.process.pid
                    )))
            }))
            .into_any_element()
    }

    fn render_modal(&self, modal: &Modal, cx: &mut Context<Self>) -> gpui_kit::AnyElement {
        let body = match modal {
            Modal::Secret { original_name } => v_flex()
                .gap_4()
                .child(modal_title(if original_name.is_some() {
                    "Edit credential"
                } else {
                    "New credential"
                }))
                .child(field("Name", Input::new(&self.secret_name)))
                .child(field(
                    "Value",
                    Textarea::new(&self.secret_value).h(px(150.)),
                ))
                .when_some(self.form_error.clone(), |this, error| {
                    this.child(error_banner(error))
                })
                .child(modal_actions(
                    "Save credential",
                    cx.listener(Self::save_secret),
                    cx,
                ))
                .into_any_element(),
            Modal::Password => v_flex()
                .gap_4()
                .child(modal_title("Change master password"))
                .child(field(
                    "New password",
                    Input::new(&self.new_password).mask_toggle(),
                ))
                .child(field(
                    "Confirm password",
                    Input::new(&self.password_confirmation).mask_toggle(),
                ))
                .when_some(self.form_error.clone(), |this, error| {
                    this.child(error_banner(error))
                })
                .child(modal_actions(
                    "Update password",
                    cx.listener(Self::save_password),
                    cx,
                ))
                .into_any_element(),
            Modal::AwsConnection => v_flex()
                .gap_4()
                .child(modal_title("Connect AWS IAM Identity Center"))
                .child(div().text_color(rgb(MUTED)).child(
                    "The portal connection and resulting login tokens stay in the encrypted vault.",
                ))
                .child(field(
                    "AWS access portal URL",
                    Input::new(&self.aws_start_url),
                ))
                .child(field(
                    "IAM Identity Center region",
                    Input::new(&self.aws_region),
                ))
                .when_some(self.form_error.clone(), |this, error| {
                    this.child(error_banner(error))
                })
                .child(modal_actions(
                    "Save and sign in",
                    cx.listener(Self::save_aws_connection),
                    cx,
                ))
                .into_any_element(),
            Modal::AwsAliases => v_flex()
                .gap_4()
                .h(px(580.))
                .overflow_hidden()
                .child(modal_title("Assign AWS profile aliases"))
                .child(
                    div().flex_1().min_h_0().overflow_hidden().child(
                        v_flex()
                            .id("aws-alias-list")
                            .size_full()
                            .gap_3()
                            .overflow_y_scrollbar()
                            .children(self.aws_aliases.iter().map(|account| {
                                card()
                                    .child(
                                        h_flex()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .font_semibold()
                                                    .child(account.account_name.clone()),
                                            )
                                            .child(
                                                div()
                                                    .font_family("monospace")
                                                    .text_color(rgb(MUTED))
                                                    .child(account.account_id.clone()),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(12.))
                                            .text_color(rgb(MUTED))
                                            .child(account.email_address.clone()),
                                    )
                                    .child(field(
                                        "Local profile alias",
                                        Input::new(&account.profile),
                                    ))
                                    .child(
                                        h_flex()
                                            .gap_3()
                                            .child(div().flex_1().child(field(
                                                "Read-only role",
                                                Input::new(&account.read_only_role),
                                            )))
                                            .child(div().flex_1().child(field(
                                                "Admin role",
                                                Input::new(&account.admin_role),
                                            ))),
                                    )
                                    .child(div().text_size(px(11.)).text_color(rgb(MUTED)).child(
                                        format!("Available roles: {}", account.roles.join(", ")),
                                    ))
                            })),
                    ),
                )
                .when_some(self.form_error.clone(), |this, error| {
                    this.child(error_banner(error))
                })
                .child(modal_actions(
                    "Save profile aliases",
                    cx.listener(Self::save_aws_aliases),
                    cx,
                ))
                .into_any_element(),
            Modal::Delete(name) => {
                let delete_name = name.clone();
                let entity = cx.entity();
                v_flex()
                    .gap_4()
                    .child(modal_title("Delete credential?"))
                    .child(format!(
                        "Permanently delete “{name}” from the encrypted vault?"
                    ))
                    .child(
                        h_flex()
                            .justify_end()
                            .gap_2()
                            .child(cancel_button(cx))
                            .child(
                                Button::new("confirm-delete")
                                    .danger()
                                    .label("Delete")
                                    .on_click(move |_, _, cx| {
                                        entity.update(cx, |this, cx| {
                                            this.delete_secret(delete_name.clone(), cx)
                                        });
                                    }),
                            ),
                    )
                    .into_any_element()
            }
        };
        div()
            .id("modal-overlay")
            .absolute()
            .inset_0()
            .flex()
            .items_center()
            .justify_center()
            .bg(gpui_kit::rgba(0x15211b66))
            .occlude()
            .child(
                div()
                    .id("modal-panel")
                    .occlude()
                    .w(px(match modal {
                        Modal::AwsAliases => 700.,
                        _ => 500.,
                    }))
                    .max_h(px(720.))
                    .p_6()
                    .bg(rgb(SURFACE))
                    .border_1()
                    .border_color(rgb(LINE))
                    .rounded(px(16.))
                    .shadow_lg()
                    .child(body),
            )
            .into_any_element()
    }
}

impl Render for MainView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self
            .toast
            .as_ref()
            .is_some_and(|toast| Instant::now() >= toast.expires_at)
        {
            self.toast = None;
        }
        self.refresh_grant_liveness(cx);
        let snapshot = Self::snapshot(cx);
        if !snapshot.vault_exists || !snapshot.unlocked {
            return v_flex()
                .size_full()
                .bg(rgb(BACKGROUND))
                .child(
                    TitleBar::new().child(
                        h_flex()
                            .w_full()
                            .h_full()
                            .pr_3()
                            .items_center()
                            .child(title_bar_brand()),
                    ),
                )
                .child(
                    div()
                        .relative()
                        .flex_1()
                        .min_h_0()
                        .child(self.render_auth(!snapshot.vault_exists, cx)),
                )
                .into_any_element();
        }
        let content = match self.view {
            View::Secrets => self.render_secrets(&snapshot, cx),
            View::Aws => self.render_aws(&snapshot, cx),
            View::Grants => self.render_grants(&snapshot, cx),
            View::Activity => self.render_activity(&snapshot),
        };
        div()
            .relative()
            .size_full()
            .bg(rgb(BACKGROUND))
            .text_color(rgb(INK))
            .child(
                v_flex()
                    .size_full()
                    .child(self.render_header(&snapshot, cx))
                    .child(
                        div()
                            .id("main-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .child(div().p_7().child(content)),
                    ),
            )
            .when_some(self.modal.clone(), |this, modal| {
                this.child(self.render_modal(&modal, cx))
            })
            .when_some(self.toast.as_ref(), |this, toast| {
                this.child(
                    div()
                        .absolute()
                        .bottom_5()
                        .left_0()
                        .right_0()
                        .flex()
                        .justify_center()
                        .child(
                            div()
                                .px_4()
                                .py_2()
                                .rounded(px(10.))
                                .bg(rgb(if toast.danger { RED } else { INK }))
                                .text_color(rgb(SURFACE))
                                .child(toast.message.clone()),
                        ),
                )
            })
            .into_any_element()
    }
}

pub struct RequestView {
    error: Option<String>,
    grant_process_choices: HashMap<String, ProcessIdentity>,
}

impl RequestView {
    pub fn new() -> Self {
        Self {
            error: None,
            grant_process_choices: HashMap::new(),
        }
    }

    fn snapshot(cx: &App) -> AppSnapshot {
        cx.global::<AppState>().snapshot()
    }

    fn respond_secret(
        &mut self,
        id: String,
        decision: ApprovalDecision,
        process: Option<ProcessIdentity>,
        cx: &mut Context<Self>,
    ) {
        let seconds = (decision == ApprovalDecision::Temporary).then_some(DEFAULT_GRANT_SECONDS);
        let result = cx
            .global::<AppState>()
            .controller()
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                controller
                    .respond(&id, decision, seconds, process)
                    .map_err(|error| error.to_string())
            });
        if result.is_ok() {
            self.grant_process_choices.remove(&id);
        }
        self.error = result.err();
        (cx.global::<AppState>().notify())();
        cx.notify();
    }

    fn respond_aws(
        &mut self,
        id: String,
        level: Option<AwsAccessLevel>,
        process: Option<ProcessIdentity>,
        cx: &mut Context<Self>,
    ) {
        let result = cx
            .global::<AppState>()
            .controller()
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())
            .and_then(|mut controller| {
                controller
                    .respond_aws(&id, level, process, Some(DEFAULT_GRANT_SECONDS))
                    .map_err(|error| error.to_string())
            });
        if result.is_ok() {
            self.grant_process_choices.remove(&id);
        }
        self.error = result.err();
        (cx.global::<AppState>().notify())();
        cx.notify();
    }

    fn select_grant_process(
        &mut self,
        request_id: String,
        process: ProcessIdentity,
        cx: &mut Context<Self>,
    ) {
        self.grant_process_choices.insert(request_id, process);
        cx.notify();
    }

    fn grant_process(
        &self,
        request_id: &str,
        process_tree: &[ProcessIdentity],
    ) -> Option<ProcessIdentity> {
        self.grant_process_choices
            .get(request_id)
            .filter(|selected| {
                process_tree
                    .iter()
                    .any(|process| same_process(selected, process))
            })
            .cloned()
            .or_else(|| default_grant_process(process_tree))
    }

    fn render_secret(
        &self,
        request: &PendingRequest,
        unlocked: bool,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let entity = cx.entity();
        let process = self.grant_process(&request.id, &request.process_tree);
        let deny_id = request.id.clone();
        let once_id = request.id.clone();
        let grant_id = request.id.clone();
        card()
            .gap_4()
            .border_color(rgb(if request.verified { LINE } else { AMBER }))
            .child(
                v_flex()
                    .gap_1()
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_semibold()
                            .child("Secret requested"),
                    )
                    .child(
                        div()
                            .font_family("monospace")
                            .text_size(px(17.))
                            .child(request.secret.clone()),
                    )
                    .child(status_pill(
                        if request.verified {
                            "Process verified"
                        } else {
                            "Process could not be verified"
                        },
                        if request.verified { GREEN } else { AMBER },
                        SURFACE_MUTED,
                    )),
            )
            .child(process_grant_selector(
                &request.id,
                &request.process_tree,
                process.as_ref(),
                request.verified,
                entity.clone(),
            ))
            .child(
                h_flex()
                    .gap_2()
                    .flex_wrap()
                    .child(Button::new("deny-secret").danger().label("Deny").on_click({
                        let entity = entity.clone();
                        move |_, _, cx| {
                            entity.update(cx, |this, cx| {
                                this.respond_secret(
                                    deny_id.clone(),
                                    ApprovalDecision::Deny,
                                    None,
                                    cx,
                                )
                            });
                        }
                    }))
                    .when(unlocked, |this| {
                        this.child(
                            Button::new("once-secret")
                                .outline()
                                .label("Allow once")
                                .on_click({
                                    let entity = entity.clone();
                                    move |_, _, cx| {
                                        entity.update(cx, |this, cx| {
                                            this.respond_secret(
                                                once_id.clone(),
                                                ApprovalDecision::Once,
                                                None,
                                                cx,
                                            )
                                        });
                                    }
                                }),
                        )
                    })
                    .when(unlocked && request.verified, |this| {
                        this.child(
                            Button::new("grant-secret")
                                .primary()
                                .label("Grant for 30 minutes")
                                .on_click(move |_, _, cx| {
                                    entity.update(cx, |this, cx| {
                                        this.respond_secret(
                                            grant_id.clone(),
                                            ApprovalDecision::Temporary,
                                            process.clone(),
                                            cx,
                                        )
                                    });
                                }),
                        )
                    })
                    .when(!unlocked, |this| {
                        this.child(
                            Button::new("unlock-main")
                                .primary()
                                .label("Open secretd to unlock")
                                .on_click(|_, _, cx| crate::runtime::open_main(cx)),
                        )
                    }),
            )
            .into_any_element()
    }

    fn render_aws_request(
        &self,
        request: &PendingAwsCredentialRequest,
        unlocked: bool,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let entity = cx.entity();
        let process = self.grant_process(&request.id, &request.process_tree);
        let deny_id = request.id.clone();
        let read_id = request.id.clone();
        let admin_id = request.id.clone();
        card()
            .gap_4()
            .border_color(rgb(if request.verified { LINE } else { AMBER }))
            .child(
                v_flex()
                    .gap_1()
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_semibold()
                            .child("AWS credentials requested"),
                    )
                    .child(
                        div()
                            .font_family("monospace")
                            .text_size(px(17.))
                            .child(format!("Profile: {}", request.profile)),
                    ),
            )
            .child(process_grant_selector(
                &request.id,
                &request.process_tree,
                process.as_ref(),
                request.verified,
                entity.clone(),
            ))
            .child(
                h_flex()
                    .gap_2()
                    .flex_wrap()
                    .child(
                        Button::new("deny-aws")
                            .danger()
                            .label(if request.verified {
                                "Deny for 30 min"
                            } else {
                                "Deny"
                            })
                            .on_click({
                                let entity = entity.clone();
                                let process = process.clone();
                                move |_, _, cx| {
                                    entity.update(cx, |this, cx| {
                                        this.respond_aws(deny_id.clone(), None, process.clone(), cx)
                                    });
                                }
                            }),
                    )
                    .when(unlocked, |this| {
                        this.child(
                            Button::new("read-aws")
                                .outline()
                                .label("Grant read-only")
                                .on_click({
                                    let entity = entity.clone();
                                    let process = process.clone();
                                    move |_, _, cx| {
                                        entity.update(cx, |this, cx| {
                                            this.respond_aws(
                                                read_id.clone(),
                                                Some(AwsAccessLevel::ReadOnly),
                                                process.clone(),
                                                cx,
                                            )
                                        });
                                    }
                                }),
                        )
                        .child(
                            Button::new("admin-aws")
                                .danger()
                                .label("Grant admin")
                                .on_click(move |_, _, cx| {
                                    entity.update(cx, |this, cx| {
                                        this.respond_aws(
                                            admin_id.clone(),
                                            Some(AwsAccessLevel::Admin),
                                            process.clone(),
                                            cx,
                                        )
                                    });
                                }),
                        )
                    })
                    .when(!unlocked, |this| {
                        this.child(
                            Button::new("unlock-main")
                                .primary()
                                .label("Open secretd to unlock")
                                .on_click(|_, _, cx| crate::runtime::open_main(cx)),
                        )
                    }),
            )
            .into_any_element()
    }
}

impl Render for RequestView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let snapshot = Self::snapshot(cx);
        let show_aws = match (snapshot.pending_aws.first(), snapshot.pending.first()) {
            (Some(aws), Some(secret)) => aws.requested_at <= secret.requested_at,
            (Some(_), None) => true,
            _ => false,
        };
        let request = if show_aws {
            snapshot
                .pending_aws
                .first()
                .map(|request| self.render_aws_request(request, snapshot.unlocked, cx))
        } else {
            snapshot
                .pending
                .first()
                .map(|request| self.render_secret(request, snapshot.unlocked, cx))
        };
        v_flex()
            .size_full()
            .bg(rgb(BACKGROUND))
            .child(
                TitleBar::new().child(
                    h_flex()
                        .w_full()
                        .h_full()
                        .pr_3()
                        .gap_2()
                        .items_center()
                        .child(title_bar_brand())
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(MUTED))
                                .child("Access request"),
                        ),
                ),
            )
            .child(
                v_flex()
                    .id("request-content")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .gap_4()
                    .p_6()
                    .child(
                        v_flex()
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(22.))
                                    .font_semibold()
                                    .child("Access request"),
                            )
                            .child(
                                div()
                                    .text_color(rgb(MUTED))
                                    .child("Review the requesting process before granting access"),
                            ),
                    )
                    .when_some(self.error.clone(), |this, error| {
                        this.child(error_banner(error))
                    })
                    .when_some(request, |this, request| this.child(request)),
            )
            .into_any_element()
    }
}

pub fn dismiss_oldest_request(cx: &mut App) {
    let snapshot = cx.global::<AppState>().snapshot();
    let deny_aws = match (snapshot.pending_aws.first(), snapshot.pending.first()) {
        (Some(aws), Some(secret)) => aws.requested_at <= secret.requested_at,
        (Some(_), None) => true,
        _ => false,
    };
    let controller = cx.global::<AppState>().controller();
    if deny_aws {
        if let Some(request) = snapshot.pending_aws.first()
            && let Ok(mut controller) = controller.lock()
        {
            let _ = controller.dismiss_aws_request(&request.id);
        }
    } else if let Some(request) = snapshot.pending.first()
        && let Ok(mut controller) = controller.lock()
    {
        let _ = controller.respond(&request.id, ApprovalDecision::Deny, None, None);
    }
    (cx.global::<AppState>().notify())();
}

fn counted_tab(label: &'static str, count: usize, color: gpui_kit::Hsla) -> Tab {
    Tab::new()
        .label(label)
        .aria_label(format!("{label}, {count}"))
        .when(count > 0, |tab| {
            tab.suffix(
                h_flex()
                    .flex_shrink_0()
                    .min_w(px(16.))
                    .h(px(16.))
                    .px_1()
                    .justify_center()
                    .rounded_full()
                    .bg(color)
                    .text_color(rgb(0xffffff))
                    .text_size(px(10.))
                    .line_height(gpui_kit::relative(1.))
                    .child(if count > 999 {
                        "999+".into()
                    } else {
                        count.to_string()
                    }),
            )
        })
}

fn field(label: impl Into<SharedString>, input: impl IntoElement + Styled) -> gpui_kit::AnyElement {
    v_flex()
        .gap_1()
        .child(
            div()
                .text_size(px(12.))
                .font_semibold()
                .text_color(rgb(MUTED))
                .child(label.into()),
        )
        .child(input.w_full())
        .into_any_element()
}

fn card() -> gpui_kit::Div {
    v_flex()
        .w_full()
        .gap_2()
        .p_4()
        .bg(rgb(SURFACE))
        .border_1()
        .border_color(rgb(LINE))
        .rounded(px(14.))
}

fn brand() -> gpui_kit::AnyElement {
    h_flex()
        .gap_2()
        .items_center()
        .child(
            div()
                .size(px(30.))
                .rounded(px(9.))
                .bg(rgb(INK))
                .text_color(rgb(SURFACE))
                .flex()
                .items_center()
                .justify_center()
                .font_semibold()
                .child("S"),
        )
        .child(
            v_flex()
                .gap_0()
                .child(div().font_semibold().text_size(px(17.)).child("secretd"))
                .child(
                    div()
                        .text_size(px(9.))
                        .text_color(rgb(MUTED))
                        .child("LOCAL ENCRYPTED VAULT"),
                ),
        )
        .into_any_element()
}

fn title_bar_brand() -> gpui_kit::AnyElement {
    h_flex()
        .gap_2()
        .items_center()
        .child(
            div()
                .size(px(24.))
                .rounded(px(7.))
                .bg(rgb(INK))
                .text_color(rgb(SURFACE))
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(12.))
                .font_semibold()
                .child("S"),
        )
        .child(div().font_semibold().text_size(px(15.)).child("secretd"))
        .into_any_element()
}

fn credential_mark() -> gpui_kit::AnyElement {
    div()
        .size(px(32.))
        .rounded(px(10.))
        .bg(rgb(GREEN_SOFT))
        .text_color(rgb(GREEN))
        .flex()
        .items_center()
        .justify_center()
        .font_semibold()
        .child("•")
        .into_any_element()
}

fn status_pill(text: &str, foreground: u32, background: u32) -> gpui_kit::AnyElement {
    div()
        .px_3()
        .py_1()
        .rounded(px(999.))
        .bg(rgb(background))
        .text_color(rgb(foreground))
        .text_size(px(11.))
        .font_semibold()
        .child(text.to_string())
        .into_any_element()
}

fn section_header(title: &str, subtitle: &str) -> gpui_kit::AnyElement {
    v_flex()
        .gap_1()
        .child(
            div()
                .text_size(px(24.))
                .font_semibold()
                .text_color(rgb(INK))
                .child(title.to_string()),
        )
        .child(div().text_color(rgb(MUTED)).child(subtitle.to_string()))
        .into_any_element()
}

fn empty_state(text: &str) -> gpui_kit::AnyElement {
    div()
        .w_full()
        .p_8()
        .border_1()
        .border_color(rgb(LINE))
        .rounded(px(14.))
        .bg(rgb(SURFACE))
        .text_center()
        .text_color(rgb(MUTED))
        .child(text.to_string())
        .into_any_element()
}

fn error_banner(error: String) -> gpui_kit::AnyElement {
    div()
        .w_full()
        .p_3()
        .rounded(px(10.))
        .bg(rgb(RED_SOFT))
        .text_color(rgb(RED))
        .child(error)
        .into_any_element()
}

fn modal_title(title: &str) -> gpui_kit::AnyElement {
    div()
        .text_size(px(22.))
        .font_semibold()
        .child(title.to_string())
        .into_any_element()
}

fn cancel_button(cx: &mut Context<MainView>) -> Button {
    Button::new("cancel-modal")
        .outline()
        .label("Cancel")
        .on_click(cx.listener(|this, _, window, cx| this.close_modal(window, cx)))
}

fn modal_actions(
    submit_label: &'static str,
    submit: impl Fn(&gpui_kit::ClickEvent, &mut Window, &mut App) + 'static,
    cx: &mut Context<MainView>,
) -> gpui_kit::AnyElement {
    h_flex()
        .justify_end()
        .gap_2()
        .child(cancel_button(cx))
        .child(
            Button::new("submit-modal")
                .primary()
                .label(submit_label)
                .on_click(submit),
        )
        .into_any_element()
}

fn action_button(
    label: &'static str,
    id: String,
    extend: bool,
    aws: bool,
    entity: Entity<MainView>,
) -> Button {
    Button::new(SharedString::from(format!("{label}-{id}")))
        .flex_shrink_0()
        .outline()
        .when(!extend, |button| button.danger())
        .label(if extend { "+15 min" } else { "Revoke" })
        .on_click(move |_, _, cx| {
            entity.update(cx, |this, cx| {
                this.mutate_grant(id.clone(), extend, aws, cx)
            });
        })
}

fn process_grant_selector(
    request_id: &str,
    processes: &[ProcessIdentity],
    selected: Option<&ProcessIdentity>,
    enabled: bool,
    entity: Entity<RequestView>,
) -> gpui_kit::AnyElement {
    let grantable = processes
        .iter()
        .filter(|process| !is_launchd_process(process))
        .rev()
        .collect::<Vec<_>>();
    let requester = processes
        .iter()
        .find(|process| !is_launchd_process(process));
    v_flex()
        .gap_2()
        .child(
            v_flex()
                .gap_1()
                .child(
                    div()
                        .text_size(px(12.))
                        .font_semibold()
                        .child(if enabled {
                            "Process boundary"
                        } else {
                            "Requesting process"
                        }),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(MUTED))
                        .child(if enabled {
                            "Choose a process to include its child processes."
                        } else {
                            "This process chain is informational because access can only be allowed once."
                        }),
                ),
        )
        .child(
            v_flex()
                .gap_1()
                .p_2()
                .rounded(px(10.))
                .border_1()
                .border_color(rgb(LINE))
                .bg(rgb(SURFACE_MUTED))
                .children(grantable.into_iter().enumerate().map(|(depth, process)| {
                    let process = process.clone();
                    let request_id = request_id.to_string();
                    let radio_id = format!("grant-process-{request_id}-{}", process.pid);
                    let is_requester = requester.is_some_and(|value| same_process(value, &process));
                    let is_selected = selected.is_some_and(|value| same_process(value, &process));
                    let process_label = compact_process_label(&process);
                    let process_details = process_details(&process);
                    let process_pid = process.pid;
                    let entity = entity.clone();
                    h_flex()
                        .gap_2()
                        .pl(px(depth as f32 * 16.))
                        .child(
                            Radio::new(radio_id)
                                .checked(is_selected)
                                .disabled(!enabled)
                                .label(process_label)
                                .tooltip(process_details)
                                .on_click(move |checked, _, cx| {
                                    if *checked {
                                        entity.update(cx, |this, cx| {
                                            this.select_grant_process(
                                                request_id.clone(),
                                                process.clone(),
                                                cx,
                                            )
                                        });
                                    }
                                }),
                        )
                        .child(
                            div()
                                .text_size(px(10.))
                                .text_color(rgb(MUTED))
                                .child(format!("PID {process_pid}")),
                        )
                        .when(is_requester, |this| {
                            this.child(
                                div()
                                    .text_size(px(10.))
                                    .text_color(rgb(GREEN))
                                    .child("requester"),
                            )
                        })
                })),
        )
        .when_some(selected.filter(|_| enabled), |this, selected| {
            let name = selected
                .executable
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or(&selected.executable);
            this.child(
                div()
                    .text_size(px(11.))
                    .text_color(rgb(GREEN))
                    .child(format!(
                        "Selected: {name} and its child processes."
                    )),
            )
        })
        .into_any_element()
}

fn compact_process_label(process: &ProcessIdentity) -> String {
    let command = process.command.trim();
    let source = if command.is_empty() {
        process.executable.trim()
    } else {
        command
    };
    let mut parts = source.split_whitespace();
    let executable = parts.next().unwrap_or(source);
    let program = executable
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(executable);
    let arguments = parts.collect::<Vec<_>>();
    let mut label = program.to_string();
    for argument in arguments.iter().take(2) {
        let argument = argument.rsplit('/').next().unwrap_or(argument);
        if label.chars().count() + argument.chars().count() + 1 > 42 {
            label.push_str(" …");
            return label;
        }
        label.push(' ');
        label.push_str(argument);
    }
    if arguments.len() > 2 {
        label.push_str(" …");
    }
    label
}

fn process_details(process: &ProcessIdentity) -> String {
    if process.command.trim().is_empty() || process.command == process.executable {
        process.executable.clone()
    } else {
        format!("{}\n{}", process.executable, process.command)
    }
}

fn default_grant_process(process_tree: &[ProcessIdentity]) -> Option<ProcessIdentity> {
    process_tree
        .iter()
        .find(|process| !is_launchd_process(process))
        .cloned()
        .or_else(|| process_tree.first().cloned())
}

fn suggested_alias(account_name: &str, account_id: &str) -> String {
    let alias = account_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if alias.is_empty() {
        format!("account-{}", &account_id[8..])
    } else {
        alias
    }
}

fn suggested_role(roles: &[String], level: AwsAccessLevel) -> String {
    let keywords: &[&str] = match level {
        AwsAccessLevel::ReadOnly => &[
            "readonly",
            "read-only",
            "viewonly",
            "view-only",
            "viewer",
            "audit",
        ],
        AwsAccessLevel::Admin => &["administrator", "admin"],
    };
    roles
        .iter()
        .find(|role| {
            let role = role.to_ascii_lowercase();
            keywords.iter().any(|keyword| role.contains(keyword))
        })
        .cloned()
        .unwrap_or_default()
}

fn duration_until(timestamp: u64) -> String {
    let seconds = timestamp
        .saturating_sub(secretd::grants::now_millis())
        .div_ceil(1_000);
    if seconds >= 60 {
        format!("{}m", seconds.div_ceil(60))
    } else {
        format!("{seconds}s")
    }
}

fn duration_until_seconds(timestamp: u64) -> String {
    let seconds = timestamp.saturating_sub(secretd::aws::now_seconds());
    if seconds >= 60 {
        format!("{}m", seconds.div_ceil(60))
    } else {
        format!("{seconds}s")
    }
}

fn duration_since(timestamp: u64) -> String {
    let seconds = secretd::grants::now_millis()
        .saturating_sub(timestamp)
        .div_ceil(1_000);
    if seconds < 10 {
        "just now".into()
    } else if seconds < 60 {
        format!("{seconds}s ago")
    } else {
        format!("{}m ago", seconds / 60)
    }
}

fn audit_label(action: AuditAction) -> &'static str {
    match action {
        AuditAction::AllowedOnce => "Allowed once",
        AuditAction::GrantedTemporarily => "Access granted",
        AuditAction::AutoGranted => "Automatically released",
        AuditAction::Denied => "Request denied",
        AuditAction::TimedOut => "Request timed out",
        AuditAction::Revoked => "Access revoked",
        AuditAction::Unblocked => "Block removed",
        AuditAction::AwsAccessChanged(AwsAccessLevel::Admin) => "Switched to admin",
        AuditAction::AwsAccessChanged(AwsAccessLevel::ReadOnly) => "Switched to read-only",
    }
}

fn tray_status(snapshot: &AppSnapshot) -> TrayStatus {
    if snapshot.unlocked {
        TrayStatus::Unlocked
    } else {
        TrayStatus::Locked
    }
}

fn should_toggle_for_tray_click(
    button: tray_icon::MouseButton,
    state: tray_icon::MouseButtonState,
) -> bool {
    button == tray_icon::MouseButton::Left && state == tray_icon::MouseButtonState::Up
}

fn rebuild_tray_menu(menu: &Menu, snapshot: &AppSnapshot) -> tray_icon::menu::Result<()> {
    while menu.remove_at(0).is_some() {}
    let pending_count = snapshot.pending.len() + snapshot.pending_aws.len();
    if pending_count > 0 {
        menu.append(&MenuItem::new(
            format!(
                "{pending_count} access request{} pending",
                if pending_count == 1 { "" } else { "s" }
            ),
            false,
            None,
        ))?;
        menu.append(&PredefinedMenuItem::separator())?;
    }
    menu.append(&MenuItem::with_id("show", "Open secretd", true, None))?;
    menu.append(&MenuItem::with_id(
        "lock",
        "Lock vault",
        snapshot.unlocked,
        None,
    ))?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&MenuItem::with_id("quit", "Quit secretd", true, None))?;
    Ok(())
}

pub fn configure_theme(cx: &mut App) {
    ThemeRegistry::global_mut(cx)
        .load_themes_from_str(CATPPUCCIN_LATTE_THEME)
        .expect("embedded Catppuccin Latte theme must be valid");
    let latte = ThemeRegistry::global(cx)
        .themes()
        .get("Catppuccin Latte")
        .cloned()
        .expect("embedded Catppuccin Latte theme must be registered");
    let theme = Theme::global_mut(cx);
    theme.apply_config(&latte);
    theme.font_size = px(14.);
    theme.radius = px(8.);
    theme.radius_lg = px(14.);
}

#[cfg(test)]
mod tests {
    use super::{compact_process_label, default_grant_process, suggested_alias, suggested_role};
    use secretd::aws::AwsAccessLevel;
    use secretd::process::ProcessIdentity;

    fn process(pid: u32, executable: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            ppid: pid.saturating_sub(1),
            started_at: format!("started-{pid}"),
            executable: executable.into(),
            command: executable.into(),
        }
    }

    #[test]
    fn account_names_become_safe_profile_aliases() {
        assert_eq!(suggested_alias("Pre Prod", "123456789012"), "pre-prod");
        assert_eq!(suggested_alias("!!!", "123456789012"), "account-9012");
    }

    #[test]
    fn discovered_roles_are_suggested_by_access_level() {
        let roles = vec!["ViewOnlyAccess".into(), "AdministratorAccess".into()];
        assert_eq!(
            suggested_role(&roles, AwsAccessLevel::ReadOnly),
            "ViewOnlyAccess"
        );
        assert_eq!(
            suggested_role(&roles, AwsAccessLevel::Admin),
            "AdministratorAccess"
        );
    }

    #[test]
    fn grant_boundary_defaults_to_the_requester_not_its_ancestor() {
        let requester = process(30, "/usr/local/bin/aws");
        let shell = process(20, "/bin/zsh");
        let launchd = process(1, "/sbin/launchd");
        let tree = vec![requester.clone(), shell, launchd];

        assert_eq!(default_grant_process(&tree), Some(requester));
    }

    #[test]
    fn process_labels_show_the_program_and_compact_arguments() {
        let mut python = process(
            30,
            "/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python",
        );
        python.command = format!("{} /opt/homebrew/bin/aws s3 ls", python.executable);

        assert_eq!(compact_process_label(&python), "Python aws s3 …");
    }
}
