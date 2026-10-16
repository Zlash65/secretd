use std::{
    collections::{HashMap, HashSet},
    error::Error,
    sync::{Arc, Mutex, mpsc::Sender},
    time::{Duration, Instant},
};

use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, Sizable as _, StyledExt as _, TITLE_BAR_HEIGHT,
    TitleBar,
    button::{Button, ButtonCustomVariant, ButtonVariants as _},
    h_flex,
    input::{Input, InputEvent, InputState, Textarea, TextareaState},
    menu::{DropdownMenu as _, PopupMenuItem},
    radio::Radio,
    scroll::ScrollableElement as _,
    spinner::Spinner,
    v_flex,
};
use gpui_kit::{
    Anchor, App, AppContext, Context, ElementId, Entity, FocusHandle, Focusable as _, Global,
    InteractiveElement as _, IntoElement, ParentElement as _, Render, Role, SharedString,
    StatefulInteractiveElement as _, Styled, Subscription, Window, div,
    prelude::FluentBuilder as _, px, relative, rgb, rgba, transparent_black,
};
use tray_icon::{
    TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use zeroize::Zeroizing;

use secretd::{
    aws::{AwsAccessLevel, AwsConfiguration, AwsLoginStatus, AwsSettingsSummary, AwsTarget},
    controller::{
        AppSnapshot, ApprovalDecision, AuditAction, Controller, PendingAwsCredentialRequest,
        PendingRequest,
    },
    grants::DEFAULT_GRANT_SECONDS,
    ipc::{RequestServer, begin_aws_login},
    paths::{default_runtime_path, default_vault_path},
    process::{ProcessIdentity, is_launchd_process, same_process},
    settings::{Appearance, Page},
};

use crate::icon::{TrayStatus, tray_icon};
use crate::preferences;
use crate::theme::{self, Palette};

const APPEARANCES: [(Appearance, &str); 3] = [
    (Appearance::System, "System"),
    (Appearance::Light, "Light"),
    (Appearance::Dark, "Dark"),
];

const SIDEBAR_WIDTH: f32 = 216.;
const CONTENT_MAX_WIDTH: f32 = 920.;

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

/// The actions and body of a main-window page or an access request.
struct PageContent {
    actions: Option<gpui_kit::AnyElement>,
    body: gpui_kit::AnyElement,
}

pub struct MainView {
    page: Page,
    /// Tracks the current page's sidebar row, where focus goes when nothing has it.
    nav_focus: FocusHandle,
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
        // Tab can't start from nothing, so focus a control once the window is drawn.
        cx.defer_in(window, |this, window, cx| this.focus_default(window, cx));
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
            // Unlocking, locking, closing a dialog, and revoking a grant remove the focused
            // control. Focus another so Tab keeps working.
            cx.on_focus_lost(window, |this, window, cx| this.focus_default(window, cx)),
        ];
        Self {
            page: preferences::settings(cx).page,
            nav_focus: cx.focus_handle(),
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

    fn set_appearance(
        &mut self,
        appearance: Appearance,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Err(error) = theme::set_appearance(appearance, window, cx) {
            self.toast(format!("Could not save appearance: {error}"), true, cx);
        }
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

    fn show_page(&mut self, page: Page, cx: &mut Context<Self>) {
        if page == Page::Grants && self.page != Page::Grants {
            self.last_grant_process_check = None;
        }
        self.page = page;
        if let Err(error) = preferences::update(cx, |settings| settings.page = page) {
            eprintln!("Could not save secretd settings: {error}");
        }
        cx.notify();
    }

    /// Focuses the current page's sidebar row, or the password field while locked.
    fn focus_default(&self, window: &mut Window, cx: &mut Context<Self>) {
        if Self::snapshot(cx).unlocked {
            self.nav_focus.focus(window, cx);
        } else {
            self.auth_password.focus_handle(cx).focus(window, cx);
        }
    }

    fn refresh_grant_liveness(&mut self, cx: &App) {
        if self.page != Page::Grants {
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
        self.show_page(Page::Aws, cx);
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

    fn render_auth(
        &self,
        creating: bool,
        palette: Palette,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .pb(TITLE_BAR_HEIGHT)
            .child(
                v_flex()
                    .w(px(340.))
                    .gap_6()
                    .child(
                        v_flex()
                            .items_center()
                            .gap_2()
                            .text_center()
                            .child(icon_tile(
                                IconName::LockKeyhole,
                                56.,
                                palette.accent,
                                palette.accent_soft,
                            ))
                            .child(
                                div()
                                    .pt_2()
                                    .text_size(px(20.))
                                    .font_semibold()
                                    .child(if creating {
                                        "Create your vault"
                                    } else {
                                        "secretd is locked"
                                    }),
                            )
                            .child(div().text_color(rgb(palette.muted)).child(if creating {
                                "Choose a master password to encrypt your vault. It can't be recovered if you forget it."
                            } else {
                                "Enter your master password to unlock your vault."
                            })),
                    )
                    .child(
                        v_flex()
                            .gap_3()
                            .child(
                                Input::new(&self.auth_password)
                                    .aria_label("Master password")
                                    .large()
                                    .mask_toggle(),
                            )
                            .when(creating, |this| {
                                this.child(
                                    Input::new(&self.auth_confirmation)
                                        .aria_label("Confirm master password")
                                        .large()
                                        .mask_toggle(),
                                )
                            })
                            .when_some(self.auth_error.clone(), |this, error| {
                                this.child(error_banner(palette, error))
                            })
                            .child(
                                Button::new("submit-auth")
                                    .primary()
                                    .large()
                                    .w_full()
                                    .label(if creating { "Create vault" } else { "Unlock" })
                                    .on_click(cx.listener(Self::submit_auth)),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(rgb(palette.muted))
                            .text_center()
                            .child("AES-256 encrypted · PBKDF2 protected"),
                    ),
            )
            .into_any_element()
    }

    fn render_sidebar(
        &self,
        snapshot: &AppSnapshot,
        palette: Palette,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let entity = cx.entity();
        let profiles = snapshot
            .aws
            .as_ref()
            .map_or(0, |aws| aws.configuration.targets.len());
        let grants = snapshot.grants.len() + snapshot.aws_grants.len() + snapshot.aws_denials.len();
        let item = |page, icon, count| {
            let active = self.page == page;
            nav_item(page, icon, count, active, palette, entity.clone())
                .when(active, |row| row.track_focus(&self.nav_focus))
        };
        v_flex()
            .w(px(SIDEBAR_WIDTH))
            .h_full()
            .flex_shrink_0()
            .px_3()
            .pt_1()
            .pb_3()
            .bg(rgb(palette.sidebar))
            .border_r_1()
            .border_color(rgb(palette.line))
            .child(
                // The pages announce themselves as tabs, like the tab bar they replaced.
                v_flex()
                    .id("pages")
                    .role(Role::TabList)
                    .child(nav_group(palette, "Vault"))
                    .child(item(Page::Aws, IconName::Cloud, profiles))
                    .child(item(
                        Page::Credentials,
                        IconName::KeyRound,
                        snapshot.secrets.len(),
                    ))
                    .child(nav_group(palette, "Access"))
                    .child(item(Page::Grants, IconName::ShieldCheck, grants))
                    .child(item(Page::Activity, IconName::Activity, 0)),
            )
            .child(div().flex_1())
            .child(
                h_flex()
                    .gap_1()
                    .child(
                        nav_row("lock-vault", IconName::Lock, "Lock vault", false, palette)
                            .flex_1()
                            .on_click(
                                cx.listener(|this, _, window, cx| this.lock_vault(window, cx)),
                            ),
                    )
                    .child(settings_button(entity.clone())),
            )
            .into_any_element()
    }

    fn render_secrets(
        &self,
        snapshot: &AppSnapshot,
        palette: Palette,
        cx: &mut Context<Self>,
    ) -> PageContent {
        let new_secret = Button::new("new-secret")
            .primary()
            .icon(IconName::Plus)
            .label("New credential")
            .on_click(cx.listener(|this, _, window, cx| this.open_secret(None, window, cx)));
        if snapshot.secrets.is_empty() {
            return PageContent {
                actions: None,
                body: empty_state(
                    palette,
                    IconName::KeyRound,
                    "No credentials yet",
                    "Store API keys, tokens, and passwords. Processes ask for them with secretd get, and you approve each request.",
                    Some(new_secret.into_any_element()),
                ),
            };
        }
        let query = Self::input_value(&self.search, cx).to_ascii_lowercase();
        let visible: Vec<_> = snapshot
            .secrets
            .iter()
            .filter(|secret| query.is_empty() || secret.name.to_ascii_lowercase().contains(&query))
            .collect();
        let mono = cx.theme().mono_font_family.clone();
        let entity = cx.entity();
        let actions = h_flex()
            // Lets the search box narrow in a narrow window.
            .min_w_0()
            .gap_2()
            .child(
                div().w(px(220.)).min_w(px(120.)).child(
                    Input::new(&self.search)
                        .prefix(Icon::new(IconName::Search).text_color(rgb(palette.muted)))
                        .cleanable(true),
                ),
            )
            .child(new_secret)
            .into_any_element();
        let body = if visible.is_empty() {
            empty_state(
                palette,
                IconName::Search,
                "No matching credentials",
                "No credential name contains that text.",
                None,
            )
        } else {
            rows_panel(
                palette,
                visible
                    .into_iter()
                    .map(|secret| {
                        let name = secret.name.clone();
                        let revealed = self
                            .revealed
                            .as_ref()
                            .filter(|(revealed, _)| revealed == &name)
                            .map(|(_, value)| value.to_string());
                        let (reveal_icon, reveal_label) = if revealed.is_some() {
                            (IconName::EyeOff, "Hide value")
                        } else {
                            (IconName::Eye, "Reveal value")
                        };
                        let reveal_entity = entity.clone();
                        let reveal_name = name.clone();
                        let menu_entity = entity.clone();
                        let menu_name = name.clone();
                        list_row()
                            .child(
                                Icon::new(IconName::KeyRound)
                                    .size(px(16.))
                                    .text_color(rgb(palette.muted)),
                            )
                            .child(
                                v_flex()
                                    .flex_1()
                                    .min_w_0()
                                    .gap_2()
                                    .child(
                                        div()
                                            .font_family(mono.clone())
                                            .text_size(px(13.))
                                            .truncate()
                                            .child(name.clone()),
                                    )
                                    .when_some(revealed, |this, value| {
                                        this.child(
                                            div()
                                                .px_2p5()
                                                .py_1p5()
                                                .rounded(px(6.))
                                                .bg(rgb(palette.surface_muted))
                                                .font_family(mono.clone())
                                                .text_size(px(13.))
                                                .child(value),
                                        )
                                    }),
                            )
                            .child(
                                Button::new(SharedString::from(format!("reveal-{name}")))
                                    .ghost()
                                    .icon(reveal_icon)
                                    .tooltip(reveal_label)
                                    .accessibility_label(format!("{reveal_label} of {name}"))
                                    .on_click(move |_, _, cx| {
                                        reveal_entity.update(cx, |this, cx| {
                                            this.reveal_secret(reveal_name.clone(), cx)
                                        });
                                    }),
                            )
                            .child(
                                Button::new(SharedString::from(format!("more-{name}")))
                                    .ghost()
                                    .icon(IconName::Ellipsis)
                                    .tooltip("More actions")
                                    .accessibility_label(format!("More actions for {name}"))
                                    .dropdown_menu_with_anchor(
                                        Anchor::TopRight,
                                        move |menu, _, _| {
                                            let edit_entity = menu_entity.clone();
                                            let edit_name = menu_name.clone();
                                            let delete_entity = menu_entity.clone();
                                            let delete_name = menu_name.clone();
                                            menu.item(
                                                PopupMenuItem::new("Edit…")
                                                    .icon(IconName::Pencil)
                                                    .on_click(move |_, window, cx| {
                                                        edit_entity.update(cx, |this, cx| {
                                                            this.open_secret(
                                                                Some(edit_name.clone()),
                                                                window,
                                                                cx,
                                                            )
                                                        });
                                                    }),
                                            )
                                            .item(
                                                PopupMenuItem::new("Delete…")
                                                    .icon(IconName::Trash)
                                                    .on_click(move |_, _, cx| {
                                                        delete_entity.update(cx, |this, cx| {
                                                            this.modal = Some(Modal::Delete(
                                                                delete_name.clone(),
                                                            ));
                                                            cx.notify();
                                                        });
                                                    }),
                                            )
                                        },
                                    ),
                            )
                    })
                    .collect(),
            )
            .into_any_element()
        };
        PageContent {
            actions: Some(actions),
            body,
        }
    }

    fn render_aws(
        &self,
        snapshot: &AppSnapshot,
        palette: Palette,
        cx: &mut Context<Self>,
    ) -> PageContent {
        let login_in_progress = matches!(
            snapshot.aws_login,
            AwsLoginStatus::Starting
                | AwsLoginStatus::AwaitingUser(_)
                | AwsLoginStatus::Discovering
        );
        let mono = cx.theme().mono_font_family.clone();
        let banner = aws_login_banner(&snapshot.aws_login, palette);
        let Some(aws) = &snapshot.aws else {
            return PageContent {
                actions: None,
                body: v_flex()
                    .flex_1()
                    .gap_6()
                    .children(banner)
                    .child(empty_state(
                        palette,
                        IconName::Cloud,
                        "Connect AWS IAM Identity Center",
                        "Sign in through your AWS access portal. secretd then issues short-lived role credentials to the processes you approve.",
                        Some(
                            Button::new("connect-aws")
                                .primary()
                                .label("Connect AWS")
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.open_aws_connection(window, cx)
                                }))
                                .into_any_element(),
                        ),
                    ))
                    .into_any_element(),
            };
        };
        let entity = cx.entity();
        let has_discovered_accounts = !aws.discovered_accounts.is_empty();
        let actions = h_flex()
            .gap_1()
            .child(
                Button::new("refresh-aws")
                    .outline()
                    .icon(IconName::RefreshCw)
                    .label(if login_in_progress {
                        "Signing in…"
                    } else if aws.logged_in {
                        "Refresh"
                    } else {
                        "Sign in"
                    })
                    .loading(login_in_progress)
                    .on_click(cx.listener(|this, _, _, cx| this.begin_aws_refresh(cx))),
            )
            .child(
                Button::new("configure-aws")
                    .ghost()
                    .icon(IconName::Ellipsis)
                    .tooltip("More actions")
                    .accessibility_label("More AWS SSO actions")
                    .disabled(login_in_progress)
                    .dropdown_menu_with_anchor(Anchor::TopRight, move |menu, _, _| {
                        let aliases_entity = entity.clone();
                        let connection_entity = entity.clone();
                        menu.when(has_discovered_accounts, |menu| {
                            menu.item(PopupMenuItem::new("Edit profile aliases…").on_click(
                                move |_, window, cx| {
                                    aliases_entity
                                        .update(cx, |this, cx| this.open_aws_aliases(window, cx));
                                },
                            ))
                        })
                        .item(
                            PopupMenuItem::new("Change SSO connection…").on_click(
                                move |_, window, cx| {
                                    connection_entity.update(cx, |this, cx| {
                                        this.open_aws_connection(window, cx)
                                    });
                                },
                            ),
                        )
                    }),
            )
            .into_any_element();
        let session = if aws.logged_in {
            let detail = aws
                .access_token_expires_at
                .filter(|expires_at| *expires_at > secretd::aws::now_seconds())
                .map(|expires_at| {
                    format!(
                        "token renews automatically ({} remaining)",
                        duration_until_seconds(expires_at)
                    )
                });
            status_label(palette, palette.green, "Signed in", detail)
        } else {
            status_label(
                palette,
                palette.amber,
                "Signed out",
                Some("sign in to request credentials".into()),
            )
        };
        let connection = section(
            palette,
            "Connection",
            None,
            rows_panel(
                palette,
                vec![
                    detail_row(
                        palette,
                        "Access portal",
                        div().truncate().child(aws.configuration.start_url.clone()),
                    ),
                    detail_row(
                        palette,
                        "Region",
                        div().child(aws.configuration.sso_region.clone()),
                    ),
                    detail_row(palette, "Session", session),
                ],
            ),
        );
        PageContent {
            actions: Some(actions),
            body: v_flex()
                .gap_7()
                .children(banner)
                .child(connection)
                .child(self.render_aws_profiles(
                    aws,
                    snapshot,
                    login_in_progress,
                    palette,
                    mono,
                    cx,
                ))
                .into_any_element(),
        }
    }

    fn render_aws_profiles(
        &self,
        aws: &AwsSettingsSummary,
        snapshot: &AppSnapshot,
        login_in_progress: bool,
        palette: Palette,
        mono: SharedString,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let message = |text: String, action: Option<gpui_kit::AnyElement>| {
            section(
                palette,
                "Profiles",
                None,
                panel(palette).child(panel_message(palette, text, action)),
            )
        };
        if !aws.discovery_complete {
            return message(
                "Sign in to discover the AWS accounts and roles assigned to you.".into(),
                None,
            );
        }
        if aws.discovered_accounts.is_empty() {
            return message(
                "AWS returned no accounts assigned to this identity.".into(),
                None,
            );
        }
        if aws.configuration.targets.is_empty() {
            return message(
                "Choose a local profile name for each AWS account assigned to you.".into(),
                Some(
                    Button::new("assign-aliases")
                        .primary()
                        .label("Assign profile aliases")
                        .disabled(login_in_progress)
                        .on_click(
                            cx.listener(|this, _, window, cx| this.open_aws_aliases(window, cx)),
                        )
                        .into_any_element(),
                ),
            );
        }
        let edit = Button::new("edit-aliases")
            .ghost()
            .small()
            .label("Edit aliases")
            .disabled(login_in_progress)
            .on_click(cx.listener(|this, _, window, cx| this.open_aws_aliases(window, cx)))
            .into_any_element();
        let header = list_row()
            .min_h(px(36.))
            .gap_4()
            .text_size(px(12.))
            .font_medium()
            .text_color(rgb(palette.muted))
            .child(div().w(relative(0.2)).child("Profile"))
            .child(div().flex_1().child("Account"))
            .child(div().w(relative(0.24)).child("Read-only role"))
            .child(div().w(relative(0.24)).child("Admin role"));
        let rows = aws.configuration.targets.iter().map(|target| {
            let account = aws
                .discovered_accounts
                .iter()
                .find(|account| account.account_id == target.account_id);
            let active = snapshot
                .aws_grants
                .iter()
                .any(|grant| grant.profile == target.profile);
            list_row()
                .gap_4()
                .child(
                    h_flex()
                        .w(relative(0.2))
                        .min_w_0()
                        .gap_2()
                        .child(
                            div()
                                .min_w_0()
                                .font_family(mono.clone())
                                .text_size(px(13.))
                                .font_semibold()
                                .truncate()
                                .child(target.profile.clone()),
                        )
                        .when(active, |this| {
                            this.child(tag("Active", palette.green, palette.green_soft))
                        }),
                )
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .child(div().truncate().child(account.map_or_else(
                            || target.account_id.clone(),
                            |account| account.account_name.clone(),
                        )))
                        .child(
                            div()
                                .font_family(mono.clone())
                                .text_size(px(12.))
                                .text_color(rgb(palette.muted))
                                .child(target.account_id.clone()),
                        ),
                )
                .child(
                    div()
                        .w(relative(0.24))
                        .text_size(px(13.))
                        .truncate()
                        .child(target.read_only_role.clone()),
                )
                .child(
                    div()
                        .w(relative(0.24))
                        .text_size(px(13.))
                        .truncate()
                        .child(target.admin_role.clone()),
                )
        });
        section(
            palette,
            "Profiles",
            Some(edit),
            rows_panel(palette, std::iter::once(header).chain(rows).collect()),
        )
    }

    fn render_grants(
        &self,
        snapshot: &AppSnapshot,
        palette: Palette,
        cx: &mut Context<Self>,
    ) -> PageContent {
        if snapshot.grants.is_empty()
            && snapshot.aws_grants.is_empty()
            && snapshot.aws_denials.is_empty()
        {
            return PageContent {
                actions: None,
                body: empty_state(
                    palette,
                    IconName::ShieldCheck,
                    "No active grants",
                    "When you grant a process access for 30 minutes, it appears here so you can extend or revoke it.",
                    None,
                ),
            };
        }
        let entity = cx.entity();
        let mono = cx.theme().mono_font_family.clone();
        let mut active = Vec::new();
        for grant in &snapshot.aws_grants {
            active.push(
                grant_row(
                    palette,
                    IconName::Cloud,
                    h_flex()
                        .gap_2()
                        .child(
                            div()
                                .min_w_0()
                                .font_family(mono.clone())
                                .text_size(px(13.))
                                .font_semibold()
                                .truncate()
                                .child(grant.profile.clone()),
                        )
                        .child(level_button(
                            grant.id.clone(),
                            &grant.profile,
                            grant.level,
                            palette,
                            entity.clone(),
                            cx,
                        )),
                    &grant.process,
                    format!("{} left", duration_until(grant.expires_at)),
                )
                .child(action_button(
                    grant.id.clone(),
                    &grant.profile,
                    true,
                    true,
                    entity.clone(),
                ))
                .child(action_button(
                    grant.id.clone(),
                    &grant.profile,
                    false,
                    true,
                    entity.clone(),
                )),
            );
        }
        for grant in &snapshot.grants {
            active.push(
                grant_row(
                    palette,
                    IconName::KeyRound,
                    div()
                        .font_family(mono.clone())
                        .text_size(px(13.))
                        .font_semibold()
                        .truncate()
                        .child(grant.resource.clone()),
                    &grant.process,
                    format!("{} left", duration_until(grant.expires_at)),
                )
                .child(action_button(
                    grant.id.clone(),
                    &grant.resource,
                    true,
                    false,
                    entity.clone(),
                ))
                .child(action_button(
                    grant.id.clone(),
                    &grant.resource,
                    false,
                    false,
                    entity.clone(),
                )),
            );
        }
        let blocked: Vec<_> = snapshot
            .aws_denials
            .iter()
            .map(|denial| {
                let denial_id = denial.id.clone();
                let entity = entity.clone();
                grant_row(
                    palette,
                    IconName::Ban,
                    div()
                        .font_family(mono.clone())
                        .text_size(px(13.))
                        .font_semibold()
                        .truncate()
                        .child(denial.profile.clone()),
                    &denial.process,
                    format!("unblocks in {}", duration_until(denial.expires_at)),
                )
                .child(
                    Button::new(SharedString::from(format!("unblock-{denial_id}")))
                        .flex_shrink_0()
                        .outline()
                        .label("Unblock")
                        .accessibility_label(format!("Unblock {}", denial.profile))
                        .on_click(move |_, _, cx| {
                            entity.update(cx, |this, cx| {
                                this.unblock_aws_denial(denial_id.clone(), cx)
                            });
                        }),
                )
            })
            .collect();
        let has_aws_grants = !snapshot.aws_grants.is_empty();
        PageContent {
            actions: None,
            body: v_flex()
                .gap_7()
                .when(!active.is_empty(), |this| {
                    this.child(section(
                        palette,
                        "Active access",
                        None,
                        v_flex()
                            .gap_2()
                            .child(rows_panel(palette, active))
                            .when(has_aws_grants, |this| {
                                this.child(footnote(
                                    palette,
                                    "Switching access applies to future credential requests. AWS credentials already issued stay valid until they expire.",
                                ))
                            }),
                    ))
                })
                .when(!blocked.is_empty(), |this| {
                    this.child(section(
                        palette,
                        "Blocked requests",
                        None,
                        v_flex()
                            .gap_2()
                            .child(rows_panel(palette, blocked))
                            .child(footnote(
                                palette,
                                "secretd won't ask about a denied process again for 30 minutes. Unblock it to be asked on its next request.",
                            )),
                    ))
                })
                .into_any_element(),
        }
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

    fn render_activity(&self, snapshot: &AppSnapshot, palette: Palette, cx: &App) -> PageContent {
        if snapshot.audit.is_empty() {
            return PageContent {
                actions: None,
                body: empty_state(
                    palette,
                    IconName::Activity,
                    "No activity yet",
                    "Requests, approvals, and revocations appear here while secretd is running.",
                    None,
                ),
            };
        }
        let mono = cx.theme().mono_font_family.clone();
        PageContent {
            actions: Some(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(palette.muted))
                    .child("Cleared when secretd quits")
                    .into_any_element(),
            ),
            body: rows_panel(
                palette,
                snapshot
                    .audit
                    .iter()
                    .map(|entry| {
                        list_row()
                            .min_h(px(44.))
                            .child(status_dot(match entry.action {
                                AuditAction::Denied
                                | AuditAction::TimedOut
                                | AuditAction::Revoked => palette.red,
                                _ => palette.green,
                            }))
                            .child(
                                div()
                                    .w(px(170.))
                                    .min_w_0()
                                    .truncate()
                                    .child(audit_label(entry.action)),
                            )
                            .child(
                                div()
                                    .w(px(180.))
                                    .min_w_0()
                                    .font_family(mono.clone())
                                    .text_size(px(13.))
                                    .truncate()
                                    .child(entry.secret.clone()),
                            )
                            .child(
                                // In a narrow window the two columns before this one give way first.
                                div()
                                    .flex_1()
                                    .min_w(px(120.))
                                    .text_size(px(13.))
                                    .text_color(rgb(palette.muted))
                                    .truncate()
                                    .child(format!(
                                        "{} · PID {}",
                                        compact_process_label(&entry.process),
                                        entry.process.pid
                                    )),
                            )
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .text_size(px(12.))
                                    .text_color(rgb(palette.muted))
                                    .child(duration_since(entry.occurred_at)),
                            )
                    })
                    .collect(),
            )
            .into_any_element(),
        }
    }

    fn render_modal(
        &self,
        modal: &Modal,
        palette: Palette,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let mono = cx.theme().mono_font_family.clone();
        let body = match modal {
            Modal::Secret { original_name } => v_flex()
                .gap_4()
                .child(modal_title(if original_name.is_some() {
                    "Edit credential"
                } else {
                    "New credential"
                }))
                .child(field(
                    palette,
                    "Name",
                    Input::new(&self.secret_name).aria_label("Name"),
                ))
                .child(field(
                    palette,
                    "Value",
                    Textarea::new(&self.secret_value)
                        .aria_label("Value")
                        .h(px(150.)),
                ))
                .when_some(self.form_error.clone(), |this, error| {
                    this.child(error_banner(palette, error))
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
                    palette,
                    "New password",
                    Input::new(&self.new_password)
                        .aria_label("New password")
                        .mask_toggle(),
                ))
                .child(field(
                    palette,
                    "Confirm password",
                    Input::new(&self.password_confirmation)
                        .aria_label("Confirm password")
                        .mask_toggle(),
                ))
                .when_some(self.form_error.clone(), |this, error| {
                    this.child(error_banner(palette, error))
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
                .child(div().text_color(rgb(palette.muted)).child(
                    "The portal connection and resulting login tokens stay in the encrypted vault.",
                ))
                .child(field(
                    palette,
                    "AWS access portal URL",
                    Input::new(&self.aws_start_url).aria_label("AWS access portal URL"),
                ))
                .child(field(
                    palette,
                    "IAM Identity Center region",
                    Input::new(&self.aws_region).aria_label("IAM Identity Center region"),
                ))
                .when_some(self.form_error.clone(), |this, error| {
                    this.child(error_banner(palette, error))
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
                // Shrinks in a short window; the account list scrolls instead.
                .min_h_0()
                .overflow_hidden()
                .child(modal_title("Assign AWS profile aliases"))
                .child(div().text_color(rgb(palette.muted)).child(
                    "Use these names as profiles in ~/.aws/config. Clear an alias to skip that account.",
                ))
                .child(
                    div().flex_1().min_h_0().overflow_hidden().child(
                        v_flex()
                            .id("aws-alias-list")
                            .size_full()
                            .gap_3()
                            .overflow_y_scrollbar()
                            .children(self.aws_aliases.iter().map(|account| {
                                panel(palette)
                                    .flex_shrink_0()
                                    .p_4()
                                    .gap_3()
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
                                                    .font_family(mono.clone())
                                                    .text_size(px(12.))
                                                    .text_color(rgb(palette.muted))
                                                    .child(account.account_id.clone()),
                                            )
                                            .child(div().flex_1())
                                            .child(
                                                div()
                                                    .min_w_0()
                                                    .text_size(px(12.))
                                                    .text_color(rgb(palette.muted))
                                                    .truncate()
                                                    .child(account.email_address.clone()),
                                            ),
                                    )
                                    .child(field(
                                        palette,
                                        "Local profile alias",
                                        Input::new(&account.profile).aria_label(format!(
                                            "Local profile alias for {}",
                                            account.account_name
                                        )),
                                    ))
                                    .child(
                                        h_flex()
                                            .gap_3()
                                            .child(div().flex_1().child(field(
                                                palette,
                                                "Read-only role",
                                                Input::new(&account.read_only_role).aria_label(
                                                    format!(
                                                        "Read-only role for {}",
                                                        account.account_name
                                                    ),
                                                ),
                                            )))
                                            .child(div().flex_1().child(field(
                                                palette,
                                                "Admin role",
                                                Input::new(&account.admin_role).aria_label(
                                                    format!(
                                                        "Admin role for {}",
                                                        account.account_name
                                                    ),
                                                ),
                                            ))),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(12.))
                                            .text_color(rgb(palette.muted))
                                            .child(format!(
                                                "Available roles: {}",
                                                account.roles.join(", ")
                                            )),
                                    )
                            })),
                    ),
                )
                .when_some(self.form_error.clone(), |this, error| {
                    this.child(error_banner(palette, error))
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
            // Leaves the title bar uncovered, so the window can still be dragged.
            .top(TITLE_BAR_HEIGHT)
            .flex()
            .items_center()
            .justify_center()
            .p_4()
            .bg(rgba(palette.overlay))
            .occlude()
            .child(
                v_flex()
                    .id("modal-panel")
                    .occlude()
                    .w(px(match modal {
                        Modal::AwsAliases => 680.,
                        _ => 480.,
                    }))
                    .max_h_full()
                    .p_6()
                    .bg(rgb(palette.surface))
                    .border_1()
                    .border_color(rgb(palette.line))
                    .rounded(px(12.))
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
        let palette = Palette::current(cx);
        if !snapshot.vault_exists || !snapshot.unlocked {
            let auth = self.render_auth(!snapshot.vault_exists, palette, cx);
            return v_flex()
                .size_full()
                .bg(rgb(palette.background))
                .text_color(rgb(palette.ink))
                .child(window_bar(palette, None))
                .child(div().flex_1().min_h_0().child(auth))
                .into_any_element();
        }
        let PageContent { actions, body } = match self.page {
            Page::Credentials => self.render_secrets(&snapshot, palette, cx),
            Page::Aws => self.render_aws(&snapshot, palette, cx),
            Page::Grants => self.render_grants(&snapshot, palette, cx),
            Page::Activity => self.render_activity(&snapshot, palette, cx),
        };
        let sidebar = self.render_sidebar(&snapshot, palette, cx);
        div()
            .relative()
            .size_full()
            .bg(rgb(palette.background))
            .text_color(rgb(palette.ink))
            .child(
                v_flex().size_full().child(window_bar(palette, None)).child(
                    h_flex().flex_1().min_h_0().child(sidebar).child(
                        div()
                            .id("main-scroll")
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_y_scrollbar()
                            .child(
                                // Fills the viewport so an empty state can center itself.
                                v_flex()
                                    .flex_grow_1()
                                    .flex_shrink_0()
                                    .w_full()
                                    .max_w(px(CONTENT_MAX_WIDTH))
                                    .mx_auto()
                                    .px_8()
                                    .py_6()
                                    .gap_6()
                                    .child(page_header(page_title(self.page), actions))
                                    .child(body),
                            ),
                    ),
                ),
            )
            .when_some(self.modal.clone(), |this, modal| {
                this.child(self.render_modal(&modal, palette, cx))
            })
            .when_some(self.toast.as_ref(), |this, toast| {
                this.child(toast_view(palette, toast))
            })
            .into_any_element()
    }
}

pub struct RequestView {
    focus_handle: FocusHandle,
    error: Option<String>,
    grant_process_choices: HashMap<String, ProcessIdentity>,
    _subscriptions: Vec<Subscription>,
}

impl RequestView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        // Tab can't start from nothing, so focus the window once it is drawn. Focusing the
        // window rather than a control keeps Enter and Space from choosing a grant boundary or
        // an answer by accident. Answer buttons are keyed by request, so answering one removes
        // it and focus comes back here rather than moving to the next request's buttons.
        cx.defer_in(window, |this, window, cx| {
            this.focus_handle.focus(window, cx)
        });
        let _subscriptions = vec![cx.on_focus_lost(window, |this, window, cx| {
            this.focus_handle.focus(window, cx)
        })];
        Self {
            focus_handle: cx.focus_handle(),
            error: None,
            grant_process_choices: HashMap::new(),
            _subscriptions,
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
        palette: Palette,
        cx: &mut Context<Self>,
    ) -> PageContent {
        let entity = cx.entity();
        let mono = cx.theme().mono_font_family.clone();
        let process = self.grant_process(&request.id, &request.process_tree);
        let deny_id = request.id.clone();
        let once_id = request.id.clone();
        let grant_id = request.id.clone();
        let body = v_flex()
            .gap_6()
            .child(request_header(
                palette,
                IconName::KeyRound,
                "Secret requested",
                div().font_family(mono).child(request.secret.clone()),
                request.verified,
            ))
            .child(process_grant_selector(
                palette,
                &request.id,
                &request.process_tree,
                process.as_ref(),
                request.verified,
                entity.clone(),
            ))
            .into_any_element();
        let actions = h_flex()
            .gap_2()
            .child(
                Button::new(SharedString::from(format!("deny-secret-{}", request.id)))
                    .outline()
                    .label("Deny")
                    .on_click({
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
                    }),
            )
            .when(unlocked, |this| {
                this.child(
                    Button::new(SharedString::from(format!("once-secret-{}", request.id)))
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
                    Button::new(SharedString::from(format!("grant-secret-{}", request.id)))
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
            })
            .into_any_element();
        PageContent {
            actions: Some(actions),
            body,
        }
    }

    fn render_aws_request(
        &self,
        request: &PendingAwsCredentialRequest,
        unlocked: bool,
        palette: Palette,
        cx: &mut Context<Self>,
    ) -> PageContent {
        let entity = cx.entity();
        let mono = cx.theme().mono_font_family.clone();
        let process = self.grant_process(&request.id, &request.process_tree);
        let deny_id = request.id.clone();
        let read_id = request.id.clone();
        let admin_id = request.id.clone();
        let body = v_flex()
            .gap_6()
            .child(request_header(
                palette,
                IconName::Cloud,
                "AWS credentials requested",
                h_flex()
                    .gap_1p5()
                    .child(div().text_color(rgb(palette.muted)).child("Profile"))
                    .child(div().font_family(mono).child(request.profile.clone())),
                request.verified,
            ))
            .child(process_grant_selector(
                palette,
                &request.id,
                &request.process_tree,
                process.as_ref(),
                request.verified,
                entity.clone(),
            ))
            .into_any_element();
        let actions = h_flex()
            .gap_2()
            .child(
                Button::new(SharedString::from(format!("deny-aws-{}", request.id)))
                    .outline()
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
                    Button::new(SharedString::from(format!("read-aws-{}", request.id)))
                        .primary()
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
                    Button::new(SharedString::from(format!("admin-aws-{}", request.id)))
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
            })
            .into_any_element();
        PageContent {
            actions: Some(actions),
            body,
        }
    }
}

impl Render for RequestView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let snapshot = Self::snapshot(cx);
        let palette = Palette::current(cx);
        let show_aws = match (snapshot.pending_aws.first(), snapshot.pending.first()) {
            (Some(aws), Some(secret)) => aws.requested_at <= secret.requested_at,
            (Some(_), None) => true,
            _ => false,
        };
        let request = if show_aws {
            snapshot
                .pending_aws
                .first()
                .map(|request| self.render_aws_request(request, snapshot.unlocked, palette, cx))
        } else {
            snapshot
                .pending
                .first()
                .map(|request| self.render_secret(request, snapshot.unlocked, palette, cx))
        };
        let (body, actions) = match request {
            Some(PageContent { actions, body }) => (Some(body), actions),
            None => (None, None),
        };
        let waiting = (snapshot.pending.len() + snapshot.pending_aws.len()).saturating_sub(1);
        v_flex()
            .track_focus(&self.focus_handle)
            .size_full()
            .bg(rgb(palette.background))
            .text_color(rgb(palette.ink))
            .child(window_bar(palette, Some("secretd · Access request")))
            .child(
                v_flex()
                    .id("request-content")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .gap_4()
                    .px_6()
                    .py_5()
                    .when_some(self.error.clone(), |this, error| {
                        this.child(error_banner(palette, error))
                    })
                    .children(body),
            )
            .when_some(actions, |this, actions| {
                this.child(
                    h_flex()
                        .flex_shrink_0()
                        .gap_4()
                        .px_6()
                        .py_4()
                        .border_t_1()
                        .border_color(rgb(palette.line))
                        .child(
                            div()
                                .flex_1()
                                .text_size(px(12.))
                                .text_color(rgb(palette.muted))
                                .when(waiting > 0, |this| {
                                    this.child(format!(
                                        "{waiting} more request{} waiting",
                                        if waiting == 1 { "" } else { "s" }
                                    ))
                                }),
                        )
                        .child(actions),
                )
            })
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

fn page_title(page: Page) -> &'static str {
    match page {
        Page::Credentials => "Credentials",
        Page::Aws => "AWS SSO",
        Page::Grants => "Grants",
        Page::Activity => "Activity",
    }
}

/// The standard title bar: a full-width strip that holds the window controls and drags the window.
/// The system doesn't draw the window's title, so a window that needs one shows `title` here.
fn window_bar(palette: Palette, title: Option<&'static str>) -> gpui_kit::AnyElement {
    TitleBar::new()
        .bg(rgb(palette.sidebar))
        .border_color(rgb(palette.line))
        .children(title.map(|title| {
            div()
                .text_size(px(13.))
                .font_medium()
                .text_color(rgb(palette.muted))
                .child(title)
        }))
        .into_any_element()
}

fn page_header(title: &'static str, actions: Option<gpui_kit::AnyElement>) -> gpui_kit::AnyElement {
    h_flex()
        .min_h(px(32.))
        .gap_3()
        .child(
            div()
                .flex_1()
                .text_size(px(20.))
                .font_semibold()
                .child(title),
        )
        .children(actions)
        .into_any_element()
}

/// A sidebar row. It is a button, so Tab reaches it and Enter or Space presses it.
fn nav_row(
    id: impl Into<ElementId>,
    icon: IconName,
    label: &'static str,
    active: bool,
    palette: Palette,
) -> gpui_kit::base::Button {
    let row = gpui_kit::base::Button::new(id)
        .accessibility_label(label)
        .h(px(30.))
        .px_2()
        .gap_2()
        .justify_start()
        .rounded(px(6.))
        // Transparent until keyboard focus tints it, so focusing doesn't shift the row.
        .border_1()
        .border_color(transparent_black())
        .focus_visible(move |style| style.border_color(rgb(palette.accent)))
        .cursor_pointer()
        .child(Icon::new(icon).size(px(16.)).text_color(rgb(if active {
            palette.accent
        } else {
            palette.muted
        })))
        .child(div().flex_1().child(label));
    if active {
        row.bg(rgb(palette.line)).font_medium()
    } else {
        row.hover(move |style| style.bg(translucent(palette.line, 0x99)))
    }
}

fn nav_group(palette: Palette, label: &'static str) -> gpui_kit::AnyElement {
    div()
        .px_2()
        .pt_4()
        .pb_1()
        .text_size(px(12.))
        .font_semibold()
        .text_color(rgb(palette.muted))
        .child(label)
        .into_any_element()
}

fn nav_item(
    page: Page,
    icon: IconName,
    count: usize,
    active: bool,
    palette: Palette,
    entity: Entity<MainView>,
) -> gpui_kit::base::Button {
    let title = page_title(page);
    nav_row(title, icon, title, active, palette)
        .role(Role::Tab)
        .aria_selected(active)
        .when(count > 0, |row| {
            row.accessibility_label(format!("{title}, {count}")).child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(palette.muted))
                    .child(count.to_string()),
            )
        })
        .on_click(move |_, _, cx| {
            entity.update(cx, |this, cx| this.show_page(page, cx));
        })
}

fn settings_button(entity: Entity<MainView>) -> gpui_kit::AnyElement {
    Button::new("settings")
        .ghost()
        .icon(IconName::Settings)
        .tooltip("Settings")
        .accessibility_label("Settings")
        .dropdown_menu_with_anchor(Anchor::BottomLeft, move |menu, _, cx| {
            let current = theme::appearance(cx);
            let menu = APPEARANCES.into_iter().fold(
                menu.label("Appearance"),
                |menu, (appearance, label)| {
                    let entity = entity.clone();
                    menu.item(
                        PopupMenuItem::new(label)
                            .checked(appearance == current)
                            .on_click(move |_, window, cx| {
                                entity.update(cx, |this, cx| {
                                    this.set_appearance(appearance, window, cx)
                                });
                            }),
                    )
                },
            );
            let entity = entity.clone();
            menu.separator()
                .item(PopupMenuItem::new("Change master password…").on_click(
                    move |_, window, cx| {
                        entity.update(cx, |this, cx| this.open_password(window, cx));
                    },
                ))
        })
        .into_any_element()
}

fn field(
    palette: Palette,
    label: impl Into<SharedString>,
    input: impl IntoElement + Styled,
) -> gpui_kit::AnyElement {
    v_flex()
        .gap_1p5()
        .child(
            div()
                .text_size(px(13.))
                .font_medium()
                .text_color(rgb(palette.muted))
                .child(label.into()),
        )
        .child(input.w_full())
        .into_any_element()
}

/// A rounded group of rows, like a macOS settings section.
fn panel(palette: Palette) -> gpui_kit::Div {
    v_flex()
        .w_full()
        .overflow_hidden()
        .rounded(px(10.))
        .border_1()
        .border_color(rgb(palette.line))
        .bg(rgb(palette.surface))
}

fn list_row() -> gpui_kit::Div {
    h_flex().w_full().min_h(px(48.)).px_4().py_2().gap_3()
}

/// A [`panel`] whose rows are separated by hairlines.
fn rows_panel(palette: Palette, rows: Vec<gpui_kit::Div>) -> gpui_kit::Div {
    panel(palette).children(rows.into_iter().enumerate().map(|(index, row)| {
        row.when(index > 0, |row| {
            row.border_t_1().border_color(rgb(palette.line))
        })
    }))
}

fn section(
    palette: Palette,
    title: &str,
    trailing: Option<gpui_kit::AnyElement>,
    body: impl IntoElement,
) -> gpui_kit::AnyElement {
    v_flex()
        .gap_2()
        .child(
            h_flex()
                .min_h(px(24.))
                .px_1()
                .child(
                    div()
                        .flex_1()
                        .text_size(px(13.))
                        .font_semibold()
                        .text_color(rgb(palette.muted))
                        .child(title.to_string()),
                )
                .children(trailing),
        )
        .child(body)
        .into_any_element()
}

fn detail_row(palette: Palette, label: &str, value: impl IntoElement) -> gpui_kit::Div {
    list_row()
        .min_h(px(44.))
        .child(
            div()
                .w(px(140.))
                .flex_shrink_0()
                .text_color(rgb(palette.muted))
                .child(label.to_string()),
        )
        .child(div().flex_1().min_w_0().child(value))
}

fn panel_message(
    palette: Palette,
    text: String,
    action: Option<gpui_kit::AnyElement>,
) -> gpui_kit::AnyElement {
    h_flex()
        .px_4()
        .py_4()
        .gap_4()
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_color(rgb(palette.muted))
                .child(text),
        )
        .children(action)
        .into_any_element()
}

fn empty_state(
    palette: Palette,
    icon: IconName,
    title: &str,
    description: &str,
    action: Option<gpui_kit::AnyElement>,
) -> gpui_kit::AnyElement {
    v_flex()
        .flex_1()
        .w_full()
        .items_center()
        .justify_center()
        .gap_2()
        // Slightly above the true center, which looks centered below the toolbar.
        .pb(px(48.))
        .text_center()
        .child(icon_tile(icon, 48., palette.muted, palette.line))
        .child(
            div()
                .pt_2()
                .text_size(px(16.))
                .font_semibold()
                .child(title.to_string()),
        )
        .child(
            div()
                .max_w(px(420.))
                .text_color(rgb(palette.muted))
                .child(description.to_string()),
        )
        .when_some(action, |this, action| {
            this.child(div().pt_3().child(action))
        })
        .into_any_element()
}

fn icon_tile(icon: IconName, size: f32, foreground: u32, background: u32) -> gpui_kit::AnyElement {
    div()
        .size(px(size))
        .flex_shrink_0()
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(size * 0.28))
        .bg(rgb(background))
        .text_color(rgb(foreground))
        .child(Icon::new(icon).size(px(size * 0.46)))
        .into_any_element()
}

fn status_dot(color: u32) -> gpui_kit::AnyElement {
    div()
        .size(px(8.))
        .flex_shrink_0()
        .rounded_full()
        .bg(rgb(color))
        .into_any_element()
}

fn status_label(
    palette: Palette,
    color: u32,
    label: &str,
    detail: Option<String>,
) -> gpui_kit::AnyElement {
    h_flex()
        .gap_2()
        .child(status_dot(color))
        .child(label.to_string())
        .when_some(detail, |this, detail| {
            this.child(
                div()
                    .min_w_0()
                    .text_color(rgb(palette.muted))
                    .truncate()
                    .child(format!("· {detail}")),
            )
        })
        .into_any_element()
}

fn tag(label: &str, foreground: u32, background: u32) -> gpui_kit::AnyElement {
    div()
        .flex_shrink_0()
        .px_1p5()
        .py(px(1.))
        .rounded(px(5.))
        .bg(rgb(background))
        .text_color(rgb(foreground))
        .text_size(px(11.))
        .font_semibold()
        .child(label.to_string())
        .into_any_element()
}

fn footnote(palette: Palette, text: &str) -> gpui_kit::AnyElement {
    div()
        .px_1()
        .text_size(px(12.))
        .text_color(rgb(palette.muted))
        .child(text.to_string())
        .into_any_element()
}

fn translucent(color: u32, alpha: u8) -> gpui_kit::Rgba {
    rgba((color << 8) | u32::from(alpha))
}

fn aws_login_banner(
    status: &AwsLoginStatus,
    palette: Palette,
) -> Option<gpui_kit::AnyElement> {
    match status {
        AwsLoginStatus::Starting => Some(progress_banner(palette, "Checking AWS session…")),
        AwsLoginStatus::Discovering => Some(progress_banner(
            palette,
            "Loading your AWS accounts and roles…",
        )),
        AwsLoginStatus::AwaitingUser(authorization) => {
            let url = authorization.url.clone();
            Some(
                h_flex()
                    .w_full()
                    .p_4()
                    .gap_4()
                    .rounded(px(10.))
                    .border_1()
                    .border_color(rgb(palette.accent))
                    .bg(rgb(palette.accent_soft))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_1()
                            .child(div().font_semibold().child("Finish signing in to AWS"))
                            .child(div().text_color(rgb(palette.muted)).child(format!(
                                "Complete sign-in in the browser on this computer. This request expires in {}.",
                                duration_until_seconds(authorization.expires_at)
                            ))),
                    )
                    .child(
                        Button::new("open-aws-login")
                            .primary()
                            .icon(IconName::ExternalLink)
                            .label("Open sign-in page")
                            .on_click(move |_, _, cx| cx.open_url(&url)),
                    )
                    .into_any_element(),
            )
        }
        AwsLoginStatus::Failed(error) => Some(error_banner(palette, error.clone())),
        AwsLoginStatus::Idle | AwsLoginStatus::LoggedIn { .. } => None,
    }
}

fn progress_banner(palette: Palette, text: &str) -> gpui_kit::AnyElement {
    h_flex()
        .w_full()
        .px_4()
        .py_3()
        .gap_3()
        .rounded(px(10.))
        .border_1()
        .border_color(rgb(palette.line))
        .bg(rgb(palette.surface))
        .child(Spinner::new().color(rgb(palette.accent).into()))
        .child(text.to_string())
        .into_any_element()
}

/// An AWS grant's access level, which opens a menu to switch it.
fn level_button(
    id: String,
    profile: &str,
    level: AwsAccessLevel,
    palette: Palette,
    entity: Entity<MainView>,
    cx: &App,
) -> gpui_kit::AnyElement {
    let (foreground, background) = match level {
        AwsAccessLevel::ReadOnly => (palette.green, palette.green_soft),
        AwsAccessLevel::Admin => (palette.red, palette.red_soft),
    };
    let label = level_label(level);
    Button::new(SharedString::from(format!("level-{id}")))
        .xsmall()
        .custom(
            ButtonCustomVariant::new(cx)
                .color(rgb(background).into())
                .foreground(rgb(foreground).into())
                .hover(rgb(background).into())
                .active(rgb(background).into()),
        )
        .label(label)
        .accessibility_label(format!("{label} access to {profile}"))
        .dropdown_caret(true)
        .dropdown_menu(move |menu, _, _| {
            [AwsAccessLevel::ReadOnly, AwsAccessLevel::Admin]
                .into_iter()
                .fold(menu, |menu, option| {
                    let entity = entity.clone();
                    let id = id.clone();
                    menu.item(
                        PopupMenuItem::new(level_label(option))
                            .checked(option == level)
                            .on_click(move |_, _, cx| {
                                if option != level {
                                    entity.update(cx, |this, cx| {
                                        this.set_aws_grant_level(id.clone(), option, cx)
                                    });
                                }
                            }),
                    )
                })
        })
        .into_any_element()
}

fn grant_row(
    palette: Palette,
    icon: IconName,
    title: impl IntoElement,
    process: &ProcessIdentity,
    remaining: String,
) -> gpui_kit::Div {
    list_row()
        .min_h(px(56.))
        .child(Icon::new(icon).size(px(16.)).text_color(rgb(palette.muted)))
        .child(
            v_flex().flex_1().min_w_0().gap_0p5().child(title).child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(palette.muted))
                    .truncate()
                    .child(format!(
                        "{} · PID {}",
                        compact_process_label(process),
                        process.pid
                    )),
            ),
        )
        .child(
            div()
                .flex_shrink_0()
                .text_size(px(12.))
                .text_color(rgb(palette.muted))
                .child(remaining),
        )
}

fn action_button(
    id: String,
    name: &str,
    extend: bool,
    aws: bool,
    entity: Entity<MainView>,
) -> Button {
    Button::new(SharedString::from(format!(
        "{}-{id}",
        if extend { "extend" } else { "revoke" }
    )))
    .flex_shrink_0()
    .when(extend, |button| {
        button
            .outline()
            .label("+15 min")
            .tooltip("Extend by 15 minutes")
            .accessibility_label(format!("+15 min for {name}"))
    })
    .when(!extend, |button| {
        button
            .danger()
            .outline()
            .label("Revoke")
            .accessibility_label(format!("Revoke access to {name}"))
    })
    .on_click(move |_, _, cx| {
        entity.update(cx, |this, cx| {
            this.mutate_grant(id.clone(), extend, aws, cx)
        });
    })
}

fn request_header(
    palette: Palette,
    icon: IconName,
    title: &str,
    subject: impl IntoElement,
    verified: bool,
) -> gpui_kit::AnyElement {
    h_flex()
        .items_start()
        .gap_4()
        .child(icon_tile(icon, 44., palette.accent, palette.accent_soft))
        .child(
            v_flex()
                .flex_1()
                .min_w_0()
                .gap_1()
                .child(
                    div()
                        .text_size(px(17.))
                        .font_semibold()
                        .child(title.to_string()),
                )
                .child(
                    // Wraps, so a long name moves the tag to its own line instead of off-screen.
                    h_flex()
                        .flex_wrap()
                        .gap_x_2()
                        .gap_y_1()
                        .child(div().min_w_0().child(subject))
                        .child(if verified {
                            tag("Verified process", palette.green, palette.green_soft)
                        } else {
                            tag("Unverified process", palette.amber, palette.amber_soft)
                        }),
                ),
        )
        .into_any_element()
}

fn toast_view(palette: Palette, toast: &Toast) -> gpui_kit::AnyElement {
    div()
        .absolute()
        .bottom_5()
        .left(px(SIDEBAR_WIDTH))
        .right_0()
        .flex()
        .justify_center()
        .child(
            div()
                .px_4()
                .py_2()
                .rounded(px(10.))
                .shadow_lg()
                .bg(rgb(if toast.danger {
                    palette.red
                } else {
                    palette.ink
                }))
                .text_color(rgb(palette.surface))
                .child(toast.message.clone()),
        )
        .into_any_element()
}

fn error_banner(palette: Palette, error: String) -> gpui_kit::AnyElement {
    div()
        .w_full()
        .px_4()
        .py_3()
        .rounded(px(10.))
        .bg(rgb(palette.red_soft))
        .text_color(rgb(palette.red))
        .child(error)
        .into_any_element()
}

fn modal_title(title: &str) -> gpui_kit::AnyElement {
    div()
        .text_size(px(18.))
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

fn process_grant_selector(
    palette: Palette,
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
                .gap_0p5()
                .px_1()
                .child(
                    div()
                        .text_size(px(13.))
                        .font_semibold()
                        .child(if enabled {
                            "Process boundary"
                        } else {
                            "Requesting process"
                        }),
                )
                .child(
                    div()
                        .text_size(px(12.))
                        .text_color(rgb(palette.muted))
                        .child(if enabled {
                            "Choose a process to include its child processes."
                        } else {
                            "This process could not be verified, so access can only be allowed once."
                        }),
                ),
        )
        .child(
            panel(palette)
                .py_2()
                .gap_1()
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
                        .pl(px(12. + depth as f32 * 16.))
                        .pr_3()
                        .py_0p5()
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
                                .text_size(px(11.))
                                .text_color(rgb(palette.muted))
                                .child(format!("PID {process_pid}")),
                        )
                        .when(is_requester, |this| {
                            this.child(tag("Requester", palette.green, palette.green_soft))
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
            this.child(footnote(
                palette,
                &format!("Selected: {name} and its child processes."),
            ))
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
    format_duration(
        timestamp
            .saturating_sub(secretd::grants::now_millis())
            .div_ceil(1_000),
    )
}

fn duration_until_seconds(timestamp: u64) -> String {
    format_duration(timestamp.saturating_sub(secretd::aws::now_seconds()))
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        return format!("{seconds}s");
    }
    let minutes = seconds.div_ceil(60);
    match (minutes / 60, minutes % 60) {
        (0, minutes) => format!("{minutes}m"),
        (hours, 0) => format!("{hours}h"),
        (hours, minutes) => format!("{hours}h {minutes}m"),
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

fn level_label(level: AwsAccessLevel) -> &'static str {
    match level {
        AwsAccessLevel::ReadOnly => "Read-only",
        AwsAccessLevel::Admin => "Admin",
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

#[cfg(test)]
mod tests {
    use super::{
        compact_process_label, default_grant_process, format_duration, suggested_alias,
        suggested_role,
    };
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
    fn durations_round_up_to_minutes_and_show_hours() {
        assert_eq!(format_duration(42), "42s");
        assert_eq!(format_duration(61), "2m");
        assert_eq!(format_duration(3_600), "1h");
        assert_eq!(format_duration(28_500), "7h 55m");
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
