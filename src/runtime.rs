use std::{
    error::Error,
    sync::mpsc::{self, Receiver, TryRecvError},
    time::Duration,
};

use gpui_kit::component::{Root, TitleBar};
use gpui_kit::{
    App, AppContext as _, Bounds, Entity, Global, KeyBinding, QuitMode, WeakEntity, WindowBounds,
    WindowHandle, WindowKind, WindowOptions, actions, px, size,
};

use crate::app::{
    AppEvent, AppState, MainView, RequestView, configure_theme, dismiss_oldest_request,
};

const MAIN_WINDOW_SIZE: (f32, f32) = (1040., 700.);
const REQUEST_WINDOW_SIZE: (f32, f32) = (620., 520.);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[cfg(target_os = "macos")]
const QUIT_KEYSTROKE: Option<&str> = Some("cmd-q");
#[cfg(not(target_os = "macos"))]
const QUIT_KEYSTROKE: Option<&str> = None;

actions!(secretd, [Quit]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestWindowAction {
    Open,
    Close,
    None,
}

#[derive(Default)]
struct Windows {
    main: Option<WindowHandle<Root>>,
    main_view: Option<WeakEntity<MainView>>,
    request: Option<WindowHandle<Root>>,
    request_view: Option<WeakEntity<RequestView>>,
    closing_request: bool,
    opened_aws_login_url: Option<String>,
}

impl Global for Windows {}

pub fn run() -> Result<(), Box<dyn Error>> {
    let (sender, receiver) = mpsc::channel();
    let show_on_launch = std::env::args().any(|argument| argument == "--show");
    let app = gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .with_quit_mode(QuitMode::Explicit);

    app.run(move |cx| {
        configure_platform_application();
        gpui_kit::init(cx);
        configure_theme(cx);
        let state = match AppState::new(sender) {
            Ok(state) => state,
            Err(error) => {
                eprintln!("Could not start secretd: {error}");
                cx.quit();
                return;
            }
        };
        cx.set_global(state);
        cx.set_global(Windows::default());
        if let Some(keystroke) = QUIT_KEYSTROKE {
            cx.bind_keys([KeyBinding::new(keystroke, Quit, None)]);
        }
        cx.on_action(|_: &Quit, cx| cx.quit());
        observe_closed_windows(cx);
        run_event_loop(receiver, cx);
        if show_on_launch {
            open_main(cx);
        }
    });
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_platform_application() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};

    if let Some(marker) = MainThreadMarker::new() {
        let application = NSApplication::sharedApplication(marker);
        application.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    }
}

#[cfg(not(target_os = "macos"))]
fn configure_platform_application() {}

fn observe_closed_windows(cx: &mut App) {
    cx.on_window_closed(|cx, id| {
        let (was_main, was_request, intentional) = {
            let windows = cx.global_mut::<Windows>();
            let was_main = windows.main.is_some_and(|window| window.window_id() == id);
            let was_request = windows
                .request
                .is_some_and(|window| window.window_id() == id);
            let intentional = windows.closing_request;
            if was_main {
                windows.main = None;
                windows.main_view = None;
            }
            if was_request {
                windows.request = None;
                windows.request_view = None;
                windows.closing_request = false;
            }
            (was_main, was_request, intentional)
        };
        if was_main {
            // The view drops its GPUI input buffers here. The controller and IPC server are global.
        }
        if was_request && !intentional {
            dismiss_oldest_request(cx);
        }
    })
    .detach();
}

fn run_event_loop(receiver: Receiver<AppEvent>, cx: &mut App) {
    cx.spawn(async move |cx| {
        loop {
            cx.background_executor().timer(POLL_INTERVAL).await;
            let mut events = Vec::new();
            loop {
                match receiver.try_recv() {
                    Ok(event) => events.push(event),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return Ok::<(), anyhow::Error>(()),
                }
            }
            cx.update(|cx| {
                for event in events {
                    dispatch(event, cx);
                }
                refresh_views(cx);
                reconcile_windows(cx);
            });
        }
    })
    .detach();
}

fn dispatch(event: AppEvent, cx: &mut App) {
    match event {
        AppEvent::Show => open_main(cx),
        AppEvent::Toggle => toggle_main(cx),
        AppEvent::Lock => {
            cx.global::<AppState>().lock();
            if let Some(view) = cx.global::<Windows>().main_view.clone() {
                let main = cx.global::<Windows>().main;
                if let Some(main) = main {
                    let _ = main.update(cx, |_, window, cx| {
                        let _ = view.update(cx, |view, cx| view.clear_sensitive(window, cx));
                    });
                }
            }
        }
        AppEvent::StateChanged => {
            cx.global::<AppState>().refresh_tray();
            let snapshot = cx.global::<AppState>().snapshot();
            match snapshot.aws_login {
                secretd::aws::AwsLoginStatus::Starting
                | secretd::aws::AwsLoginStatus::Discovering => {
                    cx.global_mut::<Windows>().opened_aws_login_url = None;
                    show_aws_login(cx);
                }
                secretd::aws::AwsLoginStatus::AwaitingUser(authorization) => {
                    show_aws_login(cx);
                    let url = authorization.url;
                    let should_open = {
                        let windows = cx.global_mut::<Windows>();
                        if windows.opened_aws_login_url.as_deref() == Some(url.as_str()) {
                            false
                        } else {
                            windows.opened_aws_login_url = Some(url.clone());
                            true
                        }
                    };
                    if should_open {
                        cx.open_url(&url);
                    }
                }
                _ => cx.global_mut::<Windows>().opened_aws_login_url = None,
            }
        }
        AppEvent::Quit => cx.quit(),
    }
}

fn show_aws_login(cx: &mut App) {
    open_main(cx);
    if let Some(view) = cx.global::<Windows>().main_view.clone() {
        let _ = view.update(cx, |view, cx| view.show_aws_login(cx));
    }
}

fn refresh_views(cx: &mut App) {
    if let Some(view) = cx.global::<Windows>().main_view.clone() {
        let _ = view.update(cx, |_, cx| cx.notify());
    }
    if let Some(view) = cx.global::<Windows>().request_view.clone() {
        let _ = view.update(cx, |_, cx| cx.notify());
    }
}

pub(crate) fn reconcile_windows(cx: &mut App) {
    let snapshot = cx.global::<AppState>().snapshot();
    let has_requests = !snapshot.pending.is_empty() || !snapshot.pending_aws.is_empty();
    let request_window_open = cx.global::<Windows>().request.is_some();
    match request_window_action(has_requests, request_window_open) {
        RequestWindowAction::Open => open_request(cx),
        RequestWindowAction::Close => close_request(cx),
        RequestWindowAction::None => {}
    }
}

fn request_window_action(has_requests: bool, request_window_open: bool) -> RequestWindowAction {
    match (has_requests, request_window_open) {
        (true, false) => RequestWindowAction::Open,
        (false, true) => RequestWindowAction::Close,
        _ => RequestWindowAction::None,
    }
}

pub(crate) fn open_main(cx: &mut App) {
    if let Some(handle) = cx.global::<Windows>().main
        && handle
            .update(cx, |_, window, _| window.activate_window())
            .is_ok()
    {
        cx.activate(true);
        return;
    }

    let bounds = Bounds::centered(
        None,
        size(px(MAIN_WINDOW_SIZE.0), px(MAIN_WINDOW_SIZE.1)),
        cx,
    );
    let mut view_entity: Option<Entity<MainView>> = None;
    let options = WindowOptions {
        titlebar: Some(TitleBar::title_bar_options()),
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(720.), px(520.))),
        ..Default::default()
    };
    match cx.open_window(options, |window, cx| {
        window.set_window_title("secretd");
        window.on_window_should_close(cx, |_, _| true);
        let view = cx.new(|cx| MainView::new(window, cx));
        view_entity = Some(view.clone());
        cx.new(|cx| Root::new(view, window, cx))
    }) {
        Ok(handle) => {
            let windows = cx.global_mut::<Windows>();
            windows.main = Some(handle);
            windows.main_view = view_entity.map(|view| view.downgrade());
            cx.activate(true);
            let _ = handle.update(cx, |_, window, _| window.activate_window());
        }
        Err(error) => eprintln!("Could not open secretd window: {error}"),
    }
}

fn toggle_main(cx: &mut App) {
    if let Some(handle) = cx.global::<Windows>().main
        && handle
            .update(cx, |_, window, _| window.remove_window())
            .is_ok()
    {
        return;
    }
    open_main(cx);
}

fn open_request(cx: &mut App) {
    if cx.global::<Windows>().request.is_some() {
        return;
    }
    let bounds = Bounds::centered(
        None,
        size(px(REQUEST_WINDOW_SIZE.0), px(REQUEST_WINDOW_SIZE.1)),
        cx,
    );
    let options = WindowOptions {
        kind: WindowKind::PopUp,
        focus: false,
        titlebar: Some(TitleBar::title_bar_options()),
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(560.), px(460.))),
        ..Default::default()
    };
    let mut view_entity: Option<Entity<RequestView>> = None;
    match cx.open_window(options, |window, cx| {
        window.set_window_title("secretd access request");
        let view = cx.new(|_| RequestView::new());
        view_entity = Some(view.clone());
        cx.new(|cx| Root::new(view, window, cx))
    }) {
        Ok(handle) => {
            let windows = cx.global_mut::<Windows>();
            windows.request = Some(handle);
            windows.request_view = view_entity.map(|view| view.downgrade());
        }
        Err(error) => eprintln!("Could not open secretd access request: {error}"),
    }
}

fn close_request(cx: &mut App) {
    let Some(handle) = cx.global::<Windows>().request else {
        return;
    };
    cx.global_mut::<Windows>().closing_request = true;
    if handle
        .update(cx, |_, window, _| window.remove_window())
        .is_err()
    {
        let windows = cx.global_mut::<Windows>();
        windows.request = None;
        windows.request_view = None;
        windows.closing_request = false;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAIN_WINDOW_SIZE, QUIT_KEYSTROKE, REQUEST_WINDOW_SIZE, RequestWindowAction,
        request_window_action,
    };

    #[test]
    fn request_window_is_compact_relative_to_the_main_window() {
        assert!(REQUEST_WINDOW_SIZE.0 < MAIN_WINDOW_SIZE.0);
        assert!(REQUEST_WINDOW_SIZE.1 < MAIN_WINDOW_SIZE.1);
        assert!(REQUEST_WINDOW_SIZE.1 >= 520.0);
    }

    #[test]
    fn existing_request_window_is_left_alone_while_requests_are_pending() {
        assert_eq!(request_window_action(true, true), RequestWindowAction::None);
    }

    #[test]
    fn request_window_tracks_pending_request_transitions() {
        assert_eq!(
            request_window_action(true, false),
            RequestWindowAction::Open
        );
        assert_eq!(
            request_window_action(false, true),
            RequestWindowAction::Close
        );
        assert_eq!(
            request_window_action(false, false),
            RequestWindowAction::None
        );
    }

    #[test]
    fn standard_window_close_is_not_bound_to_daemon_quit() {
        assert_ne!(QUIT_KEYSTROKE, Some("alt-f4"));
    }
}
