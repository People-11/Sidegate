// Sidegate: WARP-style tray popup. VPN work is done by the Go core (../core), linked in
// as a static library and driven with tab-separated lines via GpSend/GpRecv. One exe, one process.
#![windows_subsystem = "windows"]

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontFamily, FontId, Layout, Pos2, RichText, Sense, Stroke, Vec2, pos2, vec2,
};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use std::f32::consts::TAU;
use std::ffi::{CStr, CString, c_char};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute};
use windows_sys::Win32::Graphics::Gdi::{
    BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS, DeleteObject,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::{
    DefSubclassProc, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    SetWindowSubclass, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const TITLE: &str = "Sidegate VPN";
const W: f32 = 320.0;
const H: f32 = 460.0;
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

/// Show the popup just above the taskbar, bottom-right, and give it focus.
fn show(hwnd: HWND) {
    unsafe {
        let mut wa: RECT = std::mem::zeroed();
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut wa as *mut _ as _, 0);
        let mut r: RECT = std::mem::zeroed();
        GetWindowRect(hwnd, &mut r);
        let (w, h) = (r.right - r.left, r.bottom - r.top);
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            wa.right - w - 12,
            wa.bottom - h - 12,
            0,
            0,
            SWP_NOSIZE | SWP_SHOWWINDOW,
        );
        SetForegroundWindow(hwnd);
    }
}

const WM_TRAY: u32 = WM_APP + 1;

/// Window-message hook on the egui window: tray icon clicks, Explorer restarts, and shutdown.
/// On shutdown / log-off Windows allows a few seconds after WM_ENDSESSION, enough to tear down
/// and restore the system proxy properly. (Hard kills can't be caught; the PAC fail-safe covers those.)
unsafe extern "system" fn on_msg(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM, _: usize, _: usize) -> LRESULT {
    let s = shared();
    if msg == WM_ENDSESSION && wp != 0 {
        quit();
    } else if msg == s.taskbar_created {
        tray(NIM_ADD); // Explorer restarted: our icon is gone, put it back
    } else if msg == WM_TRAY {
        match lp as u32 & 0xFFFF {
            WM_LBUTTONUP => {
                // Clicking the tray icon first steals focus, which already hid us; don't pop right back.
                if unsafe { IsWindowVisible(hwnd) } != 0 {
                    hide(hwnd);
                } else if s.last_hide.lock().unwrap().elapsed() > Duration::from_millis(400) {
                    show(hwnd);
                    s.ctx.request_repaint();
                }
            }
            WM_RBUTTONUP => tray_menu(hwnd),
            _ => {}
        }
    }
    unsafe { DefSubclassProc(hwnd, msg, wp, lp) }
}

fn tray_menu(hwnd: HWND) {
    unsafe {
        let m = CreatePopupMenu();
        AppendMenuW(m, MF_STRING, 1, wide("退出").as_ptr());
        let mut pt = std::mem::zeroed();
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd); // required so the menu closes when clicking elsewhere
        let cmd = TrackPopupMenu(
            m,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        );
        DestroyMenu(m);
        PostMessageW(hwnd, WM_NULL, 0, 0);
        if cmd == 1 {
            quit();
        }
    }
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
    unsafe { ShowWindow(hwnd, SW_HIDE) };
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
        // Same 1px border and no hover/focus expansion, so the text field's text never shifts.
        s.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
        s.interaction.selectable_labels = false; // only the text field is selectable
        s.visuals.text_cursor.stroke = Stroke::new(2.0, ACCENT);
        for w in [
            &mut s.visuals.widgets.inactive,
            &mut s.visuals.widgets.hovered,
            &mut s.visuals.widgets.active,
        ] {
            w.corner_radius = CornerRadius::same(8);
            w.expansion = 0.0;
        }
        s.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.6));
        s.visuals.menu_corner_radius = CornerRadius::same(10);
        s.visuals.popup_shadow = egui::Shadow {
            offset: [0, 3],
            blur: 12,
            spread: 0,
            color: Color32::from_black_alpha(28),
        };
        s.visuals.window_stroke = Stroke::new(1.0, Color32::from_black_alpha(18));
        s.spacing.menu_margin = egui::Margin::same(6);
        // Text field: inset (sunken) counterpart of the raised surfaces.
        s.visuals.extreme_bg_color = CARD;
        s.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_black_alpha(22));
        s.spacing.button_padding = vec2(12.0, 6.0);
    });
}

// ---------- widgets ----------

/// The switch's slightly-3D look, shared by every surface: soft layered drop shadow + fill + inner rim.
fn raised(rect: egui::Rect, radius: f32, fill: Color32) -> Vec<egui::Shape> {
    let mut v: Vec<egui::Shape> = [(1.0, 22u8), (2.5, 10), (5.0, 5)]
        .iter()
        .map(|&(g, a)| {
            egui::Shape::rect_filled(
                rect.translate(vec2(0.0, 1.5)).expand(g),
                radius + g,
                Color32::from_black_alpha(a),
            )
        })
        .collect();
    v.push(egui::Shape::rect_filled(rect, radius, fill));
    v.push(egui::Shape::rect_stroke(
        rect,
        radius,
        Stroke::new(1.0, Color32::from_black_alpha(18)),
        egui::StrokeKind::Inside,
    ));
    v
}

/// Run `add` and paint a raised surface underneath whatever it laid out.
fn under<R>(
    ui: &mut egui::Ui,
    radius: f32,
    fill: Color32,
    add: impl FnOnce(&mut egui::Ui) -> egui::InnerResponse<R>,
) -> R {
    let slot = ui.painter().add(egui::Shape::Noop);
    let r = add(ui);
    ui.painter()
        .set(slot, egui::Shape::Vec(raised(r.response.rect, radius, fill)));
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
    let pulse = egui::lerp(0.5 + 0.5 * (now * 1.6).sin()..=0.5 + 0.5 * (now * 4.0).sin(), b);
    let smooth = p * p * (3.0 - 2.0 * p);
    let painter = ui.painter();
    let r = rect.height() / 2.0;

    // Halo: follows the switch position; breathes when on, pulses faster while busy.
    for i in 1..=6 {
        let grow = i as f32 * (2.5 + 1.5 * pulse);
        let a = smooth * smooth * (0.09 - i as f32 * 0.013).max(0.0);
        painter.rect_filled(rect.expand(grow), r + grow, ACCENT.gamma_multiply(a));
    }

    // Track colour follows the knob only (busy is shown by the halo), so it never flickers.
    let track = TRACK_OFF.lerp_to_gamma(ACCENT, smooth);
    painter.rect_filled(rect, r, track);
    painter.rect_stroke(
        rect,
        r,
        Stroke::new(1.0, Color32::from_black_alpha(18)),
        egui::StrokeKind::Inside,
    );

    let kr = r - 7.0;
    let c = pos2(
        egui::lerp((rect.left() + r)..=(rect.right() - r), smooth),
        rect.center().y,
    );
    painter.extend(raised(
        egui::Rect::from_center_size(c, Vec2::splat(2.0 * kr)),
        kr,
        Color32::WHITE,
    ));

    if on || b > 0.0 {
        ctx.request_repaint(); // halo animation, paced by vsync (only runs while visible)
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn menu_icon(ui: &mut egui::Ui) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(32.0), Sense::click());
    let h = ui
        .ctx()
        .animate_bool_with_time(resp.id, resp.hovered() || resp.is_pointer_button_down_on(), 0.12);
    ui.painter()
        .extend(raised(rect.shrink(1.0), 15.0, Color32::WHITE.lerp_to_gamma(CARD, h)));
    for dy in [-6.0, 0.0, 6.0] {
        let y = rect.center().y + dy;
        ui.painter().line_segment(
            [pos2(rect.center().x - 8.0, y), pos2(rect.center().x + 8.0, y)],
            Stroke::new(2.0, INK),
        );
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn logo(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let c = rect.center();
    ui.painter()
        .circle_stroke(c, size * 0.38, Stroke::new(size * 0.16, ACCENT));
    ui.painter().circle_filled(c, size * 0.12, ACCENT);
}

fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let slot = ui.painter().add(egui::Shape::Noop);
    let b = egui::Button::new(RichText::new(text).font(bold(15.0)).color(Color32::WHITE)).frame(false);
    let resp = ui
        .add_sized([ui.available_width(), 42.0], b)
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let h = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    let fill = ACCENT.lerp_to_gamma(Color32::from_rgb(0xE0, 0x6F, 0x10), h);
    ui.painter().set(slot, egui::Shape::Vec(raised(resp.rect, 10.0, fill)));
    resp
}

fn secondary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let slot = ui.painter().add(egui::Shape::Noop);
    let b = egui::Button::new(RichText::new(text).size(14.0).color(INK)).frame(false);
    let resp = ui
        .add_sized([ui.available_width(), 38.0], b)
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let h = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.12);
    ui.painter().set(
        slot,
        egui::Shape::Vec(raised(resp.rect, 10.0, Color32::WHITE.lerp_to_gamma(CARD, h))),
    );
    resp
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
    under(ui, 8.0, Color32::from_rgb(0xFD, 0xEE, 0xEE), |ui| {
        egui::Frame::new().inner_margin(vec2(10.0, 8.0)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(msg).size(12.5).color(DANGER));
        })
    });
}

// ---------- app ----------

struct App {
    st: Arc<Mutex<St>>,
    hwnd: HWND,
    was_focused: bool,
    input: String,
    bottom_h: f32,
    warmed: bool,
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
            bottom_h: 120.0,
            warmed: false,
        }
    }

    fn header(&self, ui: &mut egui::Ui, st: &St) {
        // Fixed-height row so logo, title and the 32px menu button share one centre line.
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 32.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.set_height(32.0);
                logo(ui, 22.0);
                ui.label(RichText::new("Sidegate").font(bold(17.0)).color(INK));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let resp = menu_icon(ui);
                    egui::Popup::menu(&resp).align(egui::RectAlign::BOTTOM_END).show(|ui| {
                        ui.spacing_mut().button_padding = vec2(14.0, 7.0);
                        if !st.user.is_empty() && ui.button("退出登录").clicked() {
                            send("logout", "");
                            ui.close();
                        }
                        if ui.button("退出程序").clicked() {
                            quit();
                        }
                    });
                });
            },
        );
    }

    fn setup_page(&mut self, ui: &mut egui::Ui, st: &St) {
        if self.input.is_empty() {
            self.input = st.endpoint.clone();
        }
        ui.add_space(36.0);
        ui.vertical_centered(|ui| {
            logo(ui, 64.0);
            ui.add_space(14.0);
            ui.label(RichText::new("连接到 GlobalProtect").font(bold(20.0)).color(INK));
            ui.add_space(4.0);
            ui.label(RichText::new("输入学校或公司提供的门户地址").size(13.0).color(MUTED));
        });
        ui.add_space(26.0);
        let te = ui.add(
            egui::TextEdit::singleline(&mut self.input)
                .hint_text("vpn.example.edu")
                .font(FontId::proportional(15.0))
                .margin(vec2(12.0, 10.0))
                .desired_width(f32::INFINITY),
        );
        let enter = te.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.add_space(12.0);
        if primary_button(ui, "继续").clicked() || enter {
            send("setup", self.input.trim());
        }
        if !st.msg.is_empty() {
            ui.add_space(10.0);
            banner(ui, &st.msg);
        }
    }

    /// Shown until SSO completes: the browser has the login page, we just wait for its callback.
    fn auth_page(&mut self, ui: &mut egui::Ui, st: &St) {
        let waiting_browser = st.state == "login";
        ui.add_space(48.0);
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(96.0), Sense::hover());
            let c = rect.center();
            let now = ui.input(|i| i.time) as f32;
            ui.painter().circle_filled(c, 44.0, CARD);
            ui.painter()
                .circle_stroke(c, 44.0, Stroke::new(1.0, Color32::from_black_alpha(18)));
            ui.painter().circle_stroke(c, 18.0, Stroke::new(7.0, ACCENT));
            ui.painter().circle_filled(c, 5.5, ACCENT);
            let pts: Vec<Pos2> = (0..=32)
                .map(|i| {
                    let a = now * 3.0 + i as f32 / 32.0 * TAU * 0.3;
                    c + vec2(a.cos(), a.sin()) * 44.0
                })
                .collect();
            ui.painter().add(egui::Shape::line(pts, Stroke::new(3.0, ACCENT)));
            ui.ctx().request_repaint();

            ui.add_space(22.0);
            let (title, sub) = if waiting_browser {
                (
                    "等待认证",
                    "已在浏览器中打开登录页面
完成登录后将自动连接",
                )
            } else {
                ("正在连接", "正在建立安全连接…")
            };
            ui.label(RichText::new(title).font(bold(22.0)).color(INK));
            ui.add_space(6.0);
            ui.label(RichText::new(sub).size(13.0).color(MUTED));
            ui.add_space(4.0);
            ui.label(RichText::new(&st.endpoint).size(12.0).color(MUTED));
        });
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            if secondary_button(ui, "取消").clicked() {
                send("disconnect", "");
            }
        });
    }

    fn main_page(&mut self, ui: &mut egui::Ui, st: &St) {
        let s = st.state.as_str();
        let busy = matches!(s, "login" | "connecting");
        let on = s != "off";
        ui.add_space(34.0);
        ui.vertical_centered(|ui| {
            if big_toggle(ui, on, busy).clicked() {
                send(if on { "disconnect" } else { "connect" }, "");
            }
            ui.add_space(26.0);
            let (title, sub, col) = match s {
                "on" => ("已连接", "流量正经由安全隧道传输".to_string(), ACCENT),
                "connecting" => (
                    "正在连接",
                    if st.msg.is_empty() {
                        "请稍候…".into()
                    } else {
                        st.msg.clone()
                    },
                    INK,
                ),
                _ => ("未连接", "点击开关以连接".into(), INK),
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
            egui::Frame::new()
                .fill(CARD)
                .stroke(Stroke::new(1.0, Color32::from_black_alpha(22)))
                .corner_radius(8)
                .inner_margin(vec2(14.0, 10.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 6.0;
                    info_row(ui, "账户", &st.user);
                    info_row(ui, "网关", &st.endpoint);
                    info_row(ui, "内网 IP", &st.ip);
                    info_row(ui, "代理", "HTTP :10809 · SOCKS5 :10808");
                });
        });
        let h = r.response.rect.height();
        if (h - self.bottom_h).abs() > 0.5 {
            self.bottom_h = h;
            ui.ctx().request_repaint();
        }
    }
}

impl eframe::App for App {
    // Runs even while hidden: auto-hide on focus loss and keep the tray icon in sync.
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        let focused = ctx.input(|i| i.viewport().focused.unwrap_or(false));
        if self.was_focused && !focused {
            hide(self.hwnd);
            *shared().last_hide.lock().unwrap() = Instant::now();
        }
        self.was_focused = focused;

        let st = self.st.lock().unwrap().clone();
        let on = st.state == "on";
        if shared().on.swap(on, Ordering::Relaxed) != on {
            tray(NIM_MODIFY);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        if !self.warmed {
            // Rasterize every status string's CJK glyphs up front, so the first state change
            // after a click doesn't stall a frame on font-atlas work.
            self.warmed = true;
            let text = "已连接未正在连接等待认证准备登录点击开关以流量经由安全隧道传输请稍候…在浏览器中完成已打开页面后将自动建立                        会话过期重新退出程序账户网关内网代理取消继续输入学校或公司提供的门户地址到";
            for font in [
                bold(24.0),
                bold(22.0),
                bold(20.0),
                FontId::proportional(13.0),
                FontId::proportional(12.5),
            ] {
                ui.fonts_mut(|f| f.layout_no_wrap(text.into(), font, INK));
            }
        }
        let st = self.st.lock().unwrap().clone();
        let frame = egui::Frame::new().fill(Color32::WHITE).inner_margin(vec2(18.0, 14.0));
        egui::CentralPanel::default().frame(frame).show(ui, |ui| {
            self.header(ui, &st);
            match st.state.as_str() {
                "setup" => self.setup_page(ui, &st),
                // First login has no account yet: stay on the auth page until the tunnel is up.
                "login" => self.auth_page(ui, &st),
                "connecting" if st.user.is_empty() => self.auth_page(ui, &st),
                "starting" => {
                    ui.centered_and_justified(|ui| ui.spinner());
                }
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
                    show(h);
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
                show(h);
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
        ..Default::default()
    };
    eframe::run_native(TITLE, opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
