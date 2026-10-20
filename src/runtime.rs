use std::{
    error::Error,
    sync::mpsc::{self, Receiver, TryRecvError},
    time::Duration,
};

use gpui_kit::component::{Root, TitleBar};
use gpui_kit::{
    App, AppContext as _, Bounds, Entity, Global, KeyBinding, QuitMode, WeakEntity, Window,
    WindowBounds, WindowDecorations, WindowHandle, WindowKind, WindowOptions, actions, px, size,
};

use crate::app::{AppEvent, AppState, MainView, RequestView};
use crate::preferences;
use crate::theme::{configure_theme, follow_appearance};

const MAIN_WINDOW_SIZE: (f32, f32) = (1040., 700.);
const REQUEST_WINDOW_SIZE: (f32, f32) = (640., 640.);
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
    opened_aws_login_url: Option<String>,
}

impl Global for Windows {}

pub fn run() -> Result<(), Box<dyn Error>> {
    let (sender, receiver) = mpsc::channel();
    let show_on_launch = std::env::args().any(|argument| argument == "--show");
    let app = gpui_kit::application()
        .with_assets(crate::assets::Assets)
        .with_quit_mode(QuitMode::Explicit);

    app.run(move |cx| {
        configure_platform_application();
        gpui_kit::init(cx);
        preferences::load(cx);
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

/// Keeps the green button lit on a window that can't be resized. AppKit only enables the button
/// on a resizable window, so the window becomes resizable with its size pinned and full screen
/// off, and the button loses its action: AppKit's zoom nudges a window whose size is pinned.
#[cfg(target_os = "macos")]
fn light_zoom_button(window: &Window) {
    use objc2_app_kit::{NSView, NSWindowButton, NSWindowCollectionBehavior, NSWindowStyleMask};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let Ok(handle) = HasWindowHandle::window_handle(window) else {
        return;
    };
    let RawWindowHandle::AppKit(handle) = handle.as_raw() else {
        return;
    };
    // SAFETY: GPUI's AppKit handle points at GPUI's view in this window, which outlives this
    // call, and windows open on the main thread.
    let view = unsafe { handle.ns_view.cast::<NSView>().as_ref() };
    let Some(native) = view.window() else {
        return;
    };
    let size = native.contentRectForFrameRect(native.frame()).size;
    native.setContentMinSize(size);
    native.setContentMaxSize(size);
    native.setCollectionBehavior(
        native.collectionBehavior() | NSWindowCollectionBehavior::FullScreenNone,
    );
    native.setStyleMask(native.styleMask() | NSWindowStyleMask::Resizable);
    if let Some(zoom) = native.standardWindowButton(NSWindowButton::ZoomButton) {
        // SAFETY: Clearing the action only stops the button from sending one.
        unsafe { zoom.setAction(None) };
    }
}

#[cfg(not(target_os = "macos"))]
fn light_zoom_button(_: &Window) {}

fn observe_closed_windows(cx: &mut App) {
    // The views drop their GPUI input buffers with their windows. The controller and IPC server
    // are global. Closing the request window dismisses its requests in the view.
    cx.on_window_closed(|cx, id| {
        let windows = cx.global_mut::<Windows>();
        if windows.main.is_some_and(|window| window.window_id() == id) {
            windows.main = None;
            windows.main_view = None;
        }
        if windows
            .request
            .is_some_and(|window| window.window_id() == id)
        {
            windows.request = None;
            windows.request_view = None;
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
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        // On macOS the window keeps the size it opens at: it can't be resized, zoomed, or made
        // full screen. GPUI can't fix a window's size on Linux, so there it stays resizable down
        // to this minimum.
        is_resizable: cfg!(not(target_os = "macos")),
        window_min_size: Some(size(px(720.), px(520.))),
        // On Linux the title bar draws the window controls itself, so the window manager doesn't
        // add a title bar of its own.
        window_decorations: Some(WindowDecorations::Client),
        // The title bar handles double clicks itself, so AppKit doesn't zoom the window too.
        ..TitleBar::window_options()
    };
    match cx.open_window(options, |window, cx| {
        window.set_window_title("secretd");
        window.on_window_should_close(cx, |_, _| true);
        light_zoom_button(window);
        follow_appearance(window, cx);
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
        // On macOS a pop-up stays above other windows. On X11 the window manager doesn't manage
        // pop-ups, so the window couldn't be moved, minimized, maximized, or focused. Wayland
        // already opens a pop-up as a normal window.
        kind: if cfg!(target_os = "macos") {
            WindowKind::PopUp
        } else {
            WindowKind::Normal
        },
        focus: false,
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(560.), px(460.))),
        window_decorations: Some(WindowDecorations::Client),
        ..TitleBar::window_options()
    };
    let mut view_entity: Option<Entity<RequestView>> = None;
    match cx.open_window(options, |window, cx| {
        window.set_window_title("secretd access requests");
        follow_appearance(window, cx);
        let view = cx.new(|cx| RequestView::new(window, cx));
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
    if handle
        .update(cx, |_, window, _| window.remove_window())
        .is_err()
    {
        let windows = cx.global_mut::<Windows>();
        windows.request = None;
        windows.request_view = None;
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
