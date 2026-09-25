// Sidegate: WARP-style tray popup. VPN work is done by the Go core (../core), linked in
// as a static library and driven with tab-separated lines via GpSend/GpRecv. One exe, one process.
#![windows_subsystem = "windows"]

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontFamily, FontId, Layout, Pos2, RichText, Sense, Stroke, Vec2, pos2, vec2,
};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use std::f32::consts::TAU;
use std::ffi::{CStr, CString, c_char};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{
    DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmFlush, DwmSetWindowAttribute,
};
use windows_sys::Win32::Graphics::Gdi::{
    BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS, DeleteObject,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Shell::{
    DefSubclassProc, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    SetWindowSubclass, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const TITLE: &str = "Sidegate VPN";
const W: f32 = 320.0;
const H: f32 = 400.0;
const MENU_W: f32 = 94.0; // tray right-click menu, same width as the in-app menu
const MENU_H: f32 = 44.0;
const ACCENT: Color32 = Color32::from_rgb(0xF4, 0x81, 0x20);
const INK: Color32 = Color32::from_rgb(0x1F, 0x23, 0x28);
const MUTED: Color32 = Color32::from_rgb(0x6B, 0x72, 0x80);
const CARD: Color32 = Color32::from_rgb(0xF4, 0xF5, 0xF7);
const TRACK_OFF: Color32 = Color32::from_rgb(0xD5, 0xD8, 0xDE);
const DANGER: Color32 = Color32::from_rgb(0xD9, 0x3B, 0x3B);

// ---------- core FFI ----------

unsafe extern "C" {
    fn GpSend(cmd: *const c_char);
    fn GpRecv() -> *mut c_char;
    fn GpFree(p: *mut c_char);
    fn GpCallback(url: *const c_char);
}

fn send(cmd: &str, arg: &str) {
    let c = CString::new(format!("{cmd}\t{arg}").replace(['\0', '\n'], "")).unwrap();
    unsafe { GpSend(c.as_ptr()) }
}

fn recv() -> String {
    unsafe {
        let p = GpRecv();
        let s = CStr::from_ptr(p).to_string_lossy().into_owned();
        GpFree(p);
        s
    }
}

/// Ask the core to tear down (restores system proxy), wait for it, then exit.
fn quit() -> ! {
    send("quit", "");
    tray(NIM_DELETE);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !*shared().exited.lock().unwrap() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::process::exit(0)
}

/// State the window-message hook needs; set once in App::new.
struct Shared {
    exited: Mutex<bool>,
    last_hide: Mutex<Instant>,
    ctx: egui::Context,
    hwnd: isize,
    icons: [isize; 2], // HICON: [off, on]
    on: AtomicBool,
    menu: AtomicBool, // window is currently showing the tray right-click menu
    taskbar_created: u32,
}

static SHARED: OnceLock<Shared> = OnceLock::new();

fn shared() -> &'static Shared {
    SHARED.get().unwrap()
}

#[derive(Default, Clone)]
struct St {
    state: String,
    endpoint: String,
    user: String,
    ip: String,
    msg: String,
}

// ---------- window plumbing ----------

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Logical size -> physical pixels for this window's monitor.
fn physical(hwnd: HWND, w: f32, h: f32) -> (i32, i32) {
    let s = unsafe { GetDpiForWindow(hwnd) } as f32 / 96.0;
    ((w * s).round() as i32, (h * s).round() as i32)
}

/// Make the window layered at the given opacity. Re-applied before every fade: winit rewrites
/// the ex-style and drops the layered bit.
fn set_alpha(hwnd: HWND, alpha: u8) {
    unsafe {
        SetWindowLongPtrW(
            hwnd,
            GWL_EXSTYLE,
            GetWindowLongPtrW(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED as isize,
        );
        SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA);
    }
}

static FADE: AtomicU32 = AtomicU32::new(0);

/// DWM doesn't animate this borderless popup, so fade it ourselves: in after showing, or out
/// and then hide. Starting a new fade cancels one still running.
fn fade(hwnd: HWND, show: bool) {
    const TOTAL: f32 = 0.15; // seconds
    let id = FADE.fetch_add(1, Ordering::Relaxed) + 1;
    let h = hwnd as isize;
    std::thread::spawn(move || {
        let t0 = Instant::now();
        loop {
            if FADE.load(Ordering::Relaxed) != id {
                return;
            }
            let p = (t0.elapsed().as_secs_f32() / TOTAL).min(1.0);
            let a = if show { p } else { 1.0 - p };
            unsafe { SetLayeredWindowAttributes(h as HWND, 0, (a * 255.0).round() as u8, LWA_ALPHA) };
            if p >= 1.0 {
                break;
            }
            // One step per compositor frame, i.e. at the display's refresh rate.
            if unsafe { DwmFlush() } < 0 {
                std::thread::sleep(Duration::from_millis(8));
            }
        }
        if !show && FADE.load(Ordering::Relaxed) == id {
            unsafe { ShowWindow(h as HWND, SW_HIDE) };
        }
    });
}

/// Place the window (its size given in logical px) with its bottom-right corner at (x, y),
/// then fade it in and give it focus.
fn place(hwnd: HWND, w: f32, h: f32, x: i32, y: i32) {
    let (w, h) = physical(hwnd, w, h);
    set_alpha(hwnd, 0);
    unsafe {
        SetWindowPos(hwnd, HWND_TOPMOST, x - w, y - h, w, h, SWP_NOACTIVATE);
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
    fade(hwnd, true);
}

/// Ask the running instance to show itself. Called from other processes (second launch, the
/// browser's login callback): they aren't DPI-aware, so sizing the window from there would
/// scale it wrongly; and they may hold the foreground right, which is passed on first.
fn summon(hwnd: HWND) {
    unsafe {
        AllowSetForegroundWindow(ASFW_ANY);
        PostMessageW(hwnd, WM_SHOW_REQ, 0, 0);
    }
}

/// Show the popup just above the taskbar, bottom-right, and give it focus.
fn show(hwnd: HWND) {
    let mut wa: RECT = unsafe { std::mem::zeroed() };
    unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut wa as *mut _ as _, 0) };
    place(hwnd, W, H, wa.right - 12, wa.bottom - 12);
}

const WM_TRAY: u32 = WM_APP + 1;
const WM_SHOW_REQ: u32 = WM_APP + 2;

/// Window-message hook on the egui window: tray icon clicks, Explorer restarts, and shutdown.
/// On shutdown / log-off Windows allows a few seconds after WM_ENDSESSION, enough to tear down
/// and restore the system proxy properly. (Hard kills can't be caught; the PAC fail-safe covers those.)
unsafe extern "system" fn on_msg(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM, _: usize, _: usize) -> LRESULT {
    let s = shared();
    if msg == WM_ENDSESSION && wp != 0 {
        quit();
    } else if msg == WM_SHOW_REQ {
        s.menu.store(false, Ordering::Relaxed);
        show(hwnd);
        s.ctx.request_repaint();
    } else if msg == s.taskbar_created {
        tray(NIM_ADD); // Explorer restarted: our icon is gone, put it back
    } else if msg == WM_TRAY {
        match lp as u32 & 0xFFFF {
            WM_LBUTTONUP => {
                // Clicking the tray icon first steals focus, which already hid us; don't pop right back.
                if unsafe { IsWindowVisible(hwnd) } != 0 {
                    hide(hwnd);
                } else if s.last_hide.lock().unwrap().elapsed() > Duration::from_millis(400) {
                    s.menu.store(false, Ordering::Relaxed);
                    show(hwnd);
                    s.ctx.request_repaint();
                }
            }
            WM_RBUTTONUP => {
                // App-styled menu: the same window, shrunk to menu size at the cursor.
                let mut pt = unsafe { std::mem::zeroed() };
                unsafe { GetCursorPos(&mut pt) };
                s.menu.store(true, Ordering::Relaxed);
                place(hwnd, MENU_W, MENU_H, pt.x, pt.y);
                s.ctx.request_repaint();
            }
            _ => {}
        }
    }
    unsafe { DefSubclassProc(hwnd, msg, wp, lp) }
}

/// Add / update / remove our notification-area icon.
fn tray(op: u32) {
    let s = shared();
    let on = s.on.load(Ordering::Relaxed);
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = s.hwnd as HWND;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = s.icons[on as usize] as _;
    let tip = if on {
        "Sidegate: 已连接"
    } else {
        "Sidegate: 未连接"
    };
    for (d, c) in nid.szTip.iter_mut().zip(tip.encode_utf16()) {
        *d = c;
    }
    unsafe { Shell_NotifyIconW(op, &nid) };
}

fn hide(hwnd: HWND) {
    set_alpha(hwnd, 255);
    fade(hwnd, false);
}

fn tray_icon(on: bool) -> isize {
    // Same ring + dot as icon.ico (orange = connected, grey = not), 4x4 supersampled for smooth edges.
    let c = if on { [0x20, 0x81, 0xF4] } else { [0x90, 0x90, 0x90] }; // BGR
    let n = 32usize;
    unsafe {
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = n as i32;
        bi.bmiHeader.biHeight = -(n as i32); // top-down
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        let mut bits = std::ptr::null_mut();
        let color = CreateDIBSection(
            std::ptr::null_mut(),
            &bi,
            DIB_RGB_COLORS,
            &mut bits,
            std::ptr::null_mut(),
            0,
        );
        let px = std::slice::from_raw_parts_mut(bits as *mut u8, n * n * 4);
        for y in 0..n {
            for x in 0..n {
                let mut hit = 0;
                for sy in 0..4 {
                    for sx in 0..4 {
                        let dx = x as f32 + (sx as f32 + 0.5) / 4.0 - 16.0;
                        let dy = y as f32 + (sy as f32 + 0.5) / 4.0 - 16.0;
                        let d = (dx * dx + dy * dy).sqrt();
                        if (8.6..14.1).contains(&d) || d < 4.2 {
                            hit += 1;
                        }
                    }
                }
                let a = hit * 255 / 16;
                // premultiplied BGRA
                px[(y * n + x) * 4..][..4].copy_from_slice(&[
                    (c[0] * a / 255) as u8,
                    (c[1] * a / 255) as u8,
                    (c[2] * a / 255) as u8,
                    a as u8,
                ]);
            }
        }
        let mask_bits = vec![0u8; n * n / 8];
        let mask = CreateBitmap(n as i32, n as i32, 1, 1, mask_bits.as_ptr() as _);
        let ii = ICONINFO {
            fIcon: 1,
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask,
            hbmColor: color,
        };
        let icon = CreateIconIndirect(&ii);
        DeleteObject(color);
        DeleteObject(mask);
        icon as isize
    }
}

/// Microsoft YaHei (CJK) with Segoe UI as fallback; no bundled fonts keeps the exe small.
fn load_fonts(ctx: &egui::Context) {
    let dir = std::path::PathBuf::from(std::env::var("WINDIR").unwrap_or(r"C:\Windows".into())).join("Fonts");
    let mut fonts = egui::FontDefinitions::default();
    let mut add = |family: FontFamily, files: &[&str]| {
        let mut names = vec![];
        for f in files {
            if let Ok(b) = std::fs::read(dir.join(f)) {
                fonts
                    .font_data
                    .insert(f.to_string(), Arc::new(egui::FontData::from_owned(b)));
                names.push(f.to_string());
            }
        }
        fonts.families.insert(family, names);
    };
    add(FontFamily::Proportional, &["msyh.ttc", "segoeui.ttf", "seguisym.ttf"]);
    add(FontFamily::Monospace, &["msyh.ttc", "segoeui.ttf"]);
    add(
        FontFamily::Name("bold".into()),
        &["msyhbd.ttc", "segoeuib.ttf", "msyh.ttc"],
    );
    ctx.set_fonts(fonts);
}

fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("bold".into()))
}

fn style(ctx: &egui::Context) {
    ctx.set_visuals(egui::Visuals::light());
    ctx.all_styles_mut(|s| {
        s.visuals.selection.bg_fill = ACCENT.gamma_multiply(0.35);
        // egui text is grayscale-antialiased (no ClearType); the default linear coverage makes
        // small CJK strokes thin and grey. A gamma below 1 renders them more solid.
        s.visuals.text_options.color_transfer_function = egui::epaint::FontColorTransferFunction::Gamma(0.7);
        s.interaction.selectable_labels = false; // only the text field is selectable
        s.visuals.text_cursor.stroke = Stroke::new(2.0, ACCENT);
        for w in [
            &mut s.visuals.widgets.inactive,
            &mut s.visuals.widgets.hovered,
            &mut s.visuals.widgets.active,
        ] {
            w.corner_radius = CornerRadius::same(8);
        }
        // Menu items: grey fill on hover/press, no outline.
        s.visuals.widgets.hovered.bg_stroke = Stroke::NONE;
        s.visuals.widgets.active.bg_stroke = Stroke::NONE;
        s.visuals.menu_corner_radius = CornerRadius::same(10);
        s.visuals.popup_shadow = egui::Shadow {
            offset: [0, 3],
            blur: 12,
            spread: 0,
            color: Color32::from_black_alpha(28),
        };
        s.visuals.window_stroke = Stroke::new(1.0, Color32::from_black_alpha(18));
        s.spacing.menu_margin = egui::Margin::same(6);
    });
}

// ---------- widgets ----------

// Lighting shared by raised surfaces: light comes from above, giving a soft blurred drop shadow,
// a slight top-to-bottom gradient and a faint highlight along the flat top edge.

/// Rounded-rect outline, clockwise from the top-left corner (for the gradient mesh).
fn outline(rect: egui::Rect, r: f32) -> Vec<Pos2> {
    let r = r.min(rect.width() / 2.0).min(rect.height() / 2.0);
    let corners = [
        (pos2(rect.left() + r, rect.top() + r), 180.0f32),
        (pos2(rect.right() - r, rect.top() + r), 270.0),
        (pos2(rect.right() - r, rect.bottom() - r), 0.0),
        (pos2(rect.left() + r, rect.bottom() - r), 90.0),
    ];
    corners
        .iter()
        .flat_map(|&(c, start)| (0..=8).map(move |i| c + Vec2::angled((start + i as f32 * 11.25).to_radians()) * r))
        .collect()
}

/// Rounded rect filled with a vertical gradient (fan mesh; drawn inside an anti-aliased body).
fn gradient_fill(rect: egui::Rect, r: f32, top: Color32, bottom: Color32) -> egui::Shape {
    let pts = outline(rect, r);
    let col = |y: f32| top.lerp_to_gamma(bottom, ((y - rect.top()) / rect.height()).clamp(0.0, 1.0));
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(rect.center(), col(rect.center().y));
    for p in &pts {
        mesh.colored_vertex(*p, col(p.y));
    }
    let n = pts.len() as u32;
    for i in 0..n {
        mesh.add_triangle(0, 1 + i, 1 + (i + 1) % n);
    }
    egui::Shape::mesh(mesh)
}

/// Highlight along the flat top edge, fading out a little way into the corners.
fn highlight(rect: egui::Rect, r: f32) -> Vec<egui::Shape> {
    const SWEEP: f32 = 35.0; // degrees of each corner arc covered
    let r = r.min(rect.width() / 2.0).min(rect.height() / 2.0);
    let (tl, tr) = (
        pos2(rect.left() + r, rect.top() + r),
        pos2(rect.right() - r, rect.top() + r),
    );
    let at = |c: Pos2, deg: f32| c + Vec2::angled(deg.to_radians()) * r;
    let mut pts: Vec<Pos2> = (0..=6)
        .map(|i| at(tl, 270.0 - SWEEP + SWEEP * i as f32 / 6.0))
        .collect();
    pts.extend((0..=6).map(|i| at(tr, 270.0 + SWEEP * i as f32 / 6.0)));
    // 6 arc segments, the straight top, 6 arc segments: fade over the outer 4 on each side.
    let last = pts.len() - 2;
    pts.windows(2)
        .enumerate()
        .map(|(i, p)| {
            let k = ((i.min(last - i) as f32 + 0.5) / 4.0).min(1.0);
            egui::Shape::line_segment(
                [p[0], p[1]],
                Stroke::new(1.0, Color32::from_white_alpha(64).gamma_multiply(k)),
            )
        })
        .collect()
}

fn rim(rect: egui::Rect, r: f32, color: Color32) -> egui::Shape {
    egui::Shape::rect_stroke(rect, r, Stroke::new(1.0, color), egui::StrokeKind::Inside)
}

/// egui's blurred shadow (smooth falloff, no colour banding).
fn shadow(rect: egui::Rect, r: f32, blur: u8, dy: i8, color: Color32) -> egui::Shape {
    egui::Shadow {
        offset: [0, dy],
        blur,
        spread: 0,
        color,
    }
    .as_shape(rect, r)
    .into()
}

/// Bottom colour of a raised surface's gradient.
fn shade(fill: Color32) -> Color32 {
    fill.lerp_to_gamma(Color32::BLACK, 0.06)
}

/// Raised surface (switch knob, buttons, banner); `depth` scales the drop shadow.
fn raised(rect: egui::Rect, r: f32, fill: Color32, depth: f32) -> Vec<egui::Shape> {
    let bottom = shade(fill);
    let mut v = vec![
        shadow(
            rect,
            r,
            (8.0 * depth) as u8,
            (2.0 * depth) as i8,
            Color32::from_black_alpha((40.0 * depth) as u8),
        ),
        shadow(rect, r, 2, 0, Color32::from_black_alpha(40)), // contact shadow: outline defined all round
        egui::Shape::rect_filled(rect, r, bottom),            // anti-aliased edge; the mesh sits 1px inside
        gradient_fill(rect.shrink(1.0), r - 1.0, fill, bottom),
        rim(rect, r, Color32::from_black_alpha(30)),
    ];
    v.extend(highlight(rect.shrink(1.0), r - 1.0));
    v
}

/// Inset surface (switch track, text field, info card); also a raised surface while pressed.
fn inset(rect: egui::Rect, r: f32, fill: Color32, rim_color: Color32) -> Vec<egui::Shape> {
    vec![egui::Shape::rect_filled(rect, r, fill), rim(rect, r, rim_color)]
}

const INSET_RIM: Color32 = Color32::from_black_alpha(24);
const PRESSED_RIM: Color32 = Color32::from_black_alpha(34);

/// Run `add`, then paint `surface` (built from the laid-out rect) underneath it.
fn under<R>(
    ui: &mut egui::Ui,
    surface: impl FnOnce(egui::Rect) -> Vec<egui::Shape>,
    add: impl FnOnce(&mut egui::Ui) -> egui::InnerResponse<R>,
) -> R {
    let slot = ui.painter().add(egui::Shape::Noop);
    let r = add(ui);
    ui.painter().set(slot, egui::Shape::Vec(surface(r.response.rect)));
    r.inner
}

/// The big switch. `busy` = connecting / waiting for browser login.
fn big_toggle(ui: &mut egui::Ui, on: bool, busy: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(140.0, 76.0), Sense::click());
    let ctx = ui.ctx().clone();
    let now = ctx.input(|i| i.time) as f32;
    let p = ctx.animate_bool_with_time(resp.id, on, 0.15);
    // Blend factor for the busy effects, so entering/leaving "connecting" never jumps.
    let b = ctx.animate_bool_with_time(resp.id.with("busy"), busy, 0.3);
    let pulse = egui::lerp(0.5..=0.5 + 0.5 * (now * 4.0).sin(), b);
    let smooth = p * p * (3.0 - 2.0 * p);
    let painter = ui.painter();
    let r = rect.height() / 2.0;

    // Halo: follows the switch position; steady when on, pulses while busy.
    painter.add(shadow(
        rect,
        r,
        18,
        0,
        ACCENT.gamma_multiply(smooth * smooth * (0.3 + 0.2 * pulse)),
    ));
    // Track colour follows the knob only (busy is shown by the halo), so it never flickers.
    painter.extend(inset(rect, r, TRACK_OFF.lerp_to_gamma(ACCENT, smooth), INSET_RIM));

    let kr = r - 7.0;
    let c = pos2(
        egui::lerp((rect.left() + r)..=(rect.right() - r), smooth),
        rect.center().y,
    );
    // Snap to whole physical pixels: the animated position is fractional and would blur the edge.
    let knob = egui::emath::GuiRounding::round_to_pixels(
        egui::Rect::from_center_size(c, Vec2::splat(2.0 * kr)),
        ctx.pixels_per_point(),
    );
    painter.extend(raised(knob, kr, Color32::WHITE, 1.0));

    // Continuous repaint only while busy (a steady connected state costs no CPU).
    if b > 0.0 {
        ctx.request_repaint();
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn menu_icon(ui: &mut egui::Ui) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::click());
    let h = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    let fill = Color32::WHITE.lerp_to_gamma(shade(Color32::WHITE), h);
    ui.painter().extend(if resp.is_pointer_button_down_on() {
        inset(rect.shrink(1.0), 12.0, shade(fill), PRESSED_RIM)
    } else {
        raised(rect.shrink(1.0), 12.0, fill, 0.5)
    });
    for dy in [-4.5, 0.0, 4.5] {
        let y = rect.center().y + dy;
        ui.painter().line_segment(
            [pos2(rect.center().x - 6.0, y), pos2(rect.center().x + 6.0, y)],
            Stroke::new(1.6, INK),
        );
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A menu entry: grey fill on hover/press, no frame otherwise.
fn menu_item(ui: &mut egui::Ui, text: &str) -> bool {
    ui.spacing_mut().button_padding = vec2(14.0, 7.0);
    ui.add(egui::Button::new(text).frame_when_inactive(false)).clicked()
}

fn draw_logo(p: &egui::Painter, c: Pos2, size: f32) {
    p.circle_stroke(c, size * 0.38, Stroke::new(size * 0.16, ACCENT));
    p.circle_filled(c, size * 0.12, ACCENT);
}

/// Full-width button: raised, darker on hover, pushed in while pressed.
fn button(ui: &mut egui::Ui, text: &str, primary: bool) -> egui::Response {
    let (fill, ink, font) = if primary {
        (ACCENT, Color32::WHITE, bold(15.0))
    } else {
        (Color32::WHITE, INK, FontId::proportional(14.0))
    };
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 42.0), Sense::click());
    let h = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    let fill = fill.lerp_to_gamma(shade(fill), h);
    let down = resp.is_pointer_button_down_on();
    let p = ui.painter();
    p.extend(if down {
        inset(rect, 10.0, shade(fill), PRESSED_RIM)
    } else {
        raised(rect, 10.0, fill, 1.0)
    });
    let c = rect.center() + vec2(0.0, if down { 1.0 } else { 0.0 });
    p.text(c, egui::Align2::CENTER_CENTER, text, font, ink);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Shared top half of the setup and auth pages, so the two line up exactly.
fn hero(ui: &mut egui::Ui, spin: bool, title: &str, sub: &str, sub_color: Color32) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(96.0), Sense::hover());
        let c = rect.center();
        // Grey disc behind the logo; on the auth page the spinner runs round its rim.
        ui.painter().circle_filled(c, 44.0, CARD);
        ui.painter()
            .circle_stroke(c, 44.0, Stroke::new(1.0, Color32::from_black_alpha(18)));
        draw_logo(ui.painter(), c, 64.0);
        if spin {
            let now = ui.input(|i| i.time) as f32;
            let pts: Vec<Pos2> = (0..=32)
                .map(|i| c + Vec2::angled(now * 3.0 + i as f32 / 32.0 * TAU * 0.3) * 44.0)
                .collect();
            ui.painter().add(egui::Shape::line(pts, Stroke::new(3.0, ACCENT)));
            ui.ctx().request_repaint();
        }
        ui.add_space(10.0);
        ui.label(RichText::new(title).font(bold(20.0)).color(INK));
        ui.add_space(4.0);
        ui.label(RichText::new(sub).size(13.0).color(sub_color));
    });
}

fn info_row(ui: &mut egui::Ui, k: &str, v: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(k).size(12.5).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(if v.is_empty() { "—" } else { v }).size(12.5).color(INK));
        });
    });
}

fn banner(ui: &mut egui::Ui, msg: &str) {
    under(
        ui,
        |r| raised(r, 8.0, Color32::from_rgb(0xFD, 0xEE, 0xEE), 1.0),
        |ui| {
            egui::Frame::new().inner_margin(vec2(10.0, 8.0)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(msg).size(12.5).color(DANGER));
            })
        },
    );
}

// ---------- app ----------

struct App {
    st: Arc<Mutex<St>>,
    hwnd: HWND,
    was_focused: bool,
    input: String,
    err_msg: String,   // last error shown on the setup page
    err_input: String, // input text when that error arrived
    bottom_h: f32,
    warmed: bool,
    menu_open: bool, // in-app dropdown menu
}

impl App {
    fn new(cc: &eframe::CreationContext) -> Self {
        let ctx = cc.egui_ctx.clone();
        style(&ctx);
        load_fonts(&ctx);

        let hwnd = match cc.window_handle().unwrap().as_raw() {
            RawWindowHandle::Win32(h) => h.hwnd.get() as HWND,
            _ => unreachable!(),
        };
        unsafe {
            // Win11 rounded corners; harmless no-op on Win10.
            let pref = DWMWCP_ROUND;
            DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE as u32, &pref as *const _ as _, 4);
        }

        let st = Arc::new(Mutex::new(St {
            state: "starting".into(),
            ..Default::default()
        }));
        let _ = SHARED.set(Shared {
            exited: Mutex::new(false),
            last_hide: Mutex::new(Instant::now() - Duration::from_secs(10)),
            ctx: ctx.clone(),
            hwnd: hwnd as isize,
            icons: [tray_icon(false), tray_icon(true)],
            on: AtomicBool::new(false),
            menu: AtomicBool::new(false),
            taskbar_created: unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) },
        });
        unsafe { SetWindowSubclass(hwnd, Some(on_msg), 1, 0) };
        tray(NIM_ADD);
        {
            let (st, ctx) = (st.clone(), ctx.clone());
            std::thread::spawn(move || {
                loop {
                    let line = recv();
                    let f: Vec<&str> = line.split('\t').collect();
                    if f.len() < 5 {
                        continue;
                    }
                    if f[0] == "exited" {
                        *shared().exited.lock().unwrap() = true;
                        return;
                    }
                    let s = |i: usize| f[i].to_string();
                    *st.lock().unwrap() = St {
                        state: s(0),
                        endpoint: s(1),
                        user: s(2),
                        ip: s(3),
                        msg: s(4),
                    };
                    ctx.request_repaint();
                }
            });
        }

        show(hwnd);
        App {
            st,
            hwnd,
            was_focused: false,
            input: String::new(),
            err_msg: String::new(),
            err_input: String::new(),
            bottom_h: 120.0,
            warmed: false,
            menu_open: false,
        }
    }

    fn header(&mut self, ui: &mut egui::Ui, st: &St) {
        // Fixed-height row so logo, title and the 32px menu button share one centre line.
        let menu_btn = ui
            .allocate_ui_with_layout(
                vec2(ui.available_width(), 32.0),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.set_height(32.0);
                    let (logo, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
                    draw_logo(ui.painter(), logo.center(), 22.0);
                    ui.label(RichText::new("Sidegate").font(bold(17.0)).color(INK));
                    ui.with_layout(Layout::right_to_left(Align::Center), menu_icon).inner
                },
            )
            .inner;
        if menu_btn.clicked() {
            self.menu_open = !self.menu_open;
        }
        // Our own dropdown rather than egui's Popup, which can fade in but closes instantly.
        let t = ui
            .ctx()
            .animate_bool_with_time(menu_btn.id.with("menu"), self.menu_open, 0.15);
        if t == 0.0 {
            return;
        }
        let area = egui::Area::new(menu_btn.id.with("menu_area"))
            .order(egui::Order::Foreground)
            .pivot(egui::Align2::RIGHT_TOP)
            .fixed_pos(menu_btn.rect.right_bottom() + vec2(0.0, 4.0))
            .fade_in(false)
            .interactable(self.menu_open)
            .show(ui.ctx(), |ui| {
                ui.multiply_opacity(t);
                egui::Frame::menu(ui.style())
                    .show(ui, |ui| {
                        ui.with_layout(Layout::top_down_justified(Align::Min), |ui| {
                            if !st.user.is_empty() && menu_item(ui, "退出登录") {
                                send("logout", "");
                                self.menu_open = false;
                            }
                            if menu_item(ui, "退出程序") {
                                quit();
                            }
                        })
                    })
                    .response
                    .rect
            });
        // A click anywhere outside the menu (and its button) closes it.
        let outside =
            ui.input(|i| i.pointer.any_pressed() && i.pointer.interact_pos().is_some_and(|p| !area.inner.contains(p)));
        if self.menu_open && outside && !menu_btn.contains_pointer() {
            self.menu_open = false;
        }
    }

    /// `busy` = the address is being validated ("checking"): stay here until it's known good.
    fn setup_page(&mut self, ui: &mut egui::Ui, st: &St, busy: bool) {
        if self.input.is_empty() {
            self.input = st.endpoint.clone();
        }
        // An error marks the field red and takes the hint line's place; it clears once the address is edited.
        if st.msg != self.err_msg {
            self.err_msg = st.msg.clone();
            self.err_input = self.input.clone();
        }
        let error = !st.msg.is_empty() && self.input == self.err_input;
        let (sub, sub_color) = if error {
            (st.msg.as_str(), DANGER)
        } else {
            ("输入学校或公司提供的门户地址", MUTED)
        };
        hero(ui, false, "连接到 GlobalProtect", sub, sub_color);
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            let go = button(ui, if busy { "正在验证…" } else { "继续" }, true).clicked();
            ui.add_space(12.0);
            let slot = ui.painter().add(egui::Shape::Noop);
            let te = ui.add(
                egui::TextEdit::singleline(&mut self.input)
                    .hint_text("vpn.example.edu")
                    .font(FontId::proportional(15.0))
                    .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(12, 10)))
                    .desired_width(f32::INFINITY),
            );
            let f = ui
                .ctx()
                .animate_bool_with_time(te.id.with("focus"), te.has_focus(), 0.15);
            let e = ui.ctx().animate_bool_with_time(te.id.with("error"), error, 0.15);
            let rim_color = INSET_RIM.lerp_to_gamma(ACCENT, f).lerp_to_gamma(DANGER, e);
            ui.painter()
                .set(slot, egui::Shape::Vec(inset(te.rect, 8.0, CARD, rim_color)));
            let enter = te.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (go || enter) && !busy {
                send("setup", self.input.trim());
            }
        });
    }

    /// Shown until SSO completes: the browser has the login page, we just wait for its callback.
    fn auth_page(&mut self, ui: &mut egui::Ui, st: &St) {
        let (title, sub) = if st.state == "login" {
            ("等待认证", "请在浏览器中完成登录")
        } else {
            ("正在连接", "正在建立安全连接…")
        };
        hero(ui, true, title, sub, MUTED);
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            if button(ui, "取消", false).clicked() {
                send("disconnect", "");
            }
        });
    }

    fn main_page(&mut self, ui: &mut egui::Ui, st: &St) {
        let s = st.state.as_str();
        let busy = matches!(s, "checking" | "login" | "connecting");
        let on = s != "off";
        ui.add_space(34.0);
        ui.vertical_centered(|ui| {
            if big_toggle(ui, on, busy).clicked() {
                send(if on { "disconnect" } else { "connect" }, "");
            }
            ui.add_space(26.0);
            let (title, sub, col) = match s {
                "on" => ("已连接", "流量正经由安全隧道传输", ACCENT),
                _ if busy => (
                    "正在连接",
                    if st.msg.is_empty() {
                        "请稍候…"
                    } else {
                        st.msg.as_str()
                    },
                    INK,
                ),
                _ => ("未连接", "点击开关以连接", INK),
            };
            ui.label(RichText::new(title).font(bold(24.0)).color(col));
            ui.add_space(2.0);
            ui.label(RichText::new(sub).size(13.0).color(MUTED));
        });

        // Pin card (+ error banner) to the bottom using last frame's measured height.
        ui.add_space((ui.available_height() - self.bottom_h).max(0.0));
        let r = ui.vertical(|ui| {
            if s == "off" && !st.msg.is_empty() {
                banner(ui, &st.msg);
                ui.add_space(10.0);
            }
            under(
                ui,
                |r| inset(r, 8.0, CARD, INSET_RIM),
                |ui| {
                    egui::Frame::new().inner_margin(vec2(14.0, 10.0)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.spacing_mut().item_spacing.y = 6.0;
                        info_row(ui, "账户", &st.user);
                        info_row(ui, "网关", &st.endpoint);
                        info_row(ui, "内网 IP", &st.ip);
                        info_row(ui, "代理", "HTTP :10809 · SOCKS5 :10808");
                    })
                },
            );
        });
        let h = r.response.rect.height();
        if (h - self.bottom_h).abs() > 0.5 {
            self.bottom_h = h;
            ui.ctx().request_repaint();
        }
    }

    /// The tray right-click menu: the same window, shrunk to menu size at the cursor.
    fn tray_menu_page(&mut self, ui: &mut egui::Ui) {
        let frame = egui::Frame::new().fill(Color32::WHITE).inner_margin(6);
        egui::CentralPanel::default().frame(frame).show(ui, |ui| {
            ui.with_layout(Layout::top_down_justified(Align::Min), |ui| {
                if menu_item(ui, "退出程序") {
                    quit();
                }
            });
        });
    }
}

impl eframe::App for App {
    // Runs even while hidden: auto-hide on focus loss and keep the tray icon in sync.
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        // Frame pacing: wait for the next compositor frame here (a kernel wait) instead of
        // the GL driver's vsync, which busy-waits (~2.4 ms of CPU per frame on NVIDIA).
        unsafe { DwmFlush() };
        let focused = ctx.input(|i| i.viewport().focused.unwrap_or(false));
        if self.was_focused && !focused {
            hide(self.hwnd); // the menu flag stays set while it fades out; every show resets it
            self.menu_open = false;
            *shared().last_hide.lock().unwrap() = Instant::now();
        }
        self.was_focused = focused;

        let on = self.st.lock().unwrap().state == "on";
        if shared().on.swap(on, Ordering::Relaxed) != on {
            tray(NIM_MODIFY);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        if shared().menu.load(Ordering::Relaxed) {
            return self.tray_menu_page(ui);
        }
        if !self.warmed {
            // Rasterize the status strings' CJK glyphs up front, so the first state change
            // after a click doesn't stall a frame on font-atlas work.
            self.warmed = true;
            let text = "已连接未正在验证等待认证点击开关以流量经由安全隧道传输请稍候…在浏览器中完成登录建立\
                        会话过期重新退出程序账户网关内网代理取消继续输入学校或公司提供的门户地址到\
                        找不该服务器检查是否确无法超时证书效网关或启用";
            for font in [
                bold(24.0),
                bold(20.0),
                FontId::proportional(13.0),
                FontId::proportional(12.5),
            ] {
                ui.fonts_mut(|f| f.layout_no_wrap(text.into(), font, INK));
            }
        }
        let st = self.st.lock().unwrap().clone();
        // Bottom margin equals the side margin, so the bottom button / info card sits as far
        // from the bottom edge as from the sides.
        let margin = egui::Margin {
            left: 18,
            right: 18,
            top: 14,
            bottom: 18,
        };
        let frame = egui::Frame::new().fill(Color32::WHITE).inner_margin(margin);
        egui::CentralPanel::default().frame(frame).show(ui, |ui| {
            self.header(ui, &st);
            // Without an account (first login), validation stays on the setup page and the
            // rest of the login on the auth page, so the switch page only appears once connected.
            match (st.state.as_str(), st.user.is_empty()) {
                ("starting", _) => {
                    ui.centered_and_justified(|ui| ui.spinner());
                }
                ("setup", _) => self.setup_page(ui, &st, false),
                ("checking", true) => self.setup_page(ui, &st, true),
                ("login", _) | ("connecting", true) => self.auth_page(ui, &st),
                _ => self.main_page(ui, &st),
            }
        });
    }
}

fn main() -> eframe::Result {
    // The browser launches us as "Sidegate.exe --callback globalprotectcallback:..." after SSO;
    // hand the URL to the running instance over loopback and exit.
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--callback" {
        if let Ok(c) = CString::new(args[2].as_str()) {
            unsafe {
                GpCallback(c.as_ptr());
                let h = FindWindowW(std::ptr::null(), wide(TITLE).as_ptr());
                if !h.is_null() {
                    summon(h);
                }
            }
        }
        return Ok(());
    }
    // Single instance: a second double-click just pops up the running one.
    unsafe {
        CreateMutexW(std::ptr::null(), 0, wide("Local\\SidegateGUI").as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let h = FindWindowW(std::ptr::null(), wide(TITLE).as_ptr());
            if !h.is_null() {
                summon(h);
            }
            return Ok(());
        }
    }
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(TITLE)
            .with_inner_size([W, H])
            .with_decorations(false)
            .with_resizable(false)
            .with_always_on_top()
            .with_taskbar(false)
            .with_visible(false), // we position it ourselves, then show
        glow_options: eframe::egui_glow::GlowConfiguration {
            vsync: false, // paced by DwmFlush in logic() instead
            ..Default::default()
        },
        ..Default::default()
    };
    eframe::run_native(TITLE, opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
