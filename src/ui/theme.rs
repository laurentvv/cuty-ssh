//! Central visual theme: palette, spacing, rounding, fonts and Phosphor icon glyphs.
//!
//! Applied once at startup through [`apply`]; widgets elsewhere should pull colors
//! from here instead of hardcoding RGB triples.

use egui::{
    Color32, Context, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Response,
    RichText, Stroke, TextStyle, Ui, Vec2,
};
use std::sync::Arc;

pub const ACCENT: Color32 = Color32::from_rgb(47, 129, 247);
pub const ACCENT_STRONG: Color32 = Color32::from_rgb(31, 111, 235);
pub const SUCCESS: Color32 = Color32::from_rgb(63, 185, 80);
pub const DANGER: Color32 = Color32::from_rgb(248, 81, 73);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(139, 148, 158);
pub const BORDER: Color32 = Color32::from_rgb(48, 54, 61);
pub const SURFACE: Color32 = Color32::from_rgb(22, 27, 34);
pub const SURFACE_HOVER: Color32 = Color32::from_rgb(33, 40, 52);
pub const SURFACE_ACTIVE: Color32 = Color32::from_rgb(40, 50, 66);
pub const PANEL_BG: Color32 = Color32::from_rgb(13, 17, 23);
pub const TOOLBAR_BG: Color32 = Color32::from_rgb(16, 20, 28);

pub const RADIUS: u8 = 6;

/// Phosphor icon glyphs (private-use codepoints of `assets/fonts/Phosphor.ttf`).
/// The font is registered as a fallback of the proportional family, so they render
/// inside any regular text.
pub mod icons {
    pub const SIDEBAR: &str = "\u{EC24}";
    pub const PLUS: &str = "\u{E3D4}";
    pub const LIGHTNING: &str = "\u{E2DE}";
    pub const SEARCH: &str = "\u{E30C}";
    pub const FOLDER: &str = "\u{E24A}";
    pub const KEY: &str = "\u{E2D6}";
    pub const SHIELD: &str = "\u{E40C}";
    pub const NETWORK: &str = "\u{EDDE}";
    pub const AUDIT: &str = "\u{EADC}";
    pub const REPLAY: &str = "\u{E3D0}";
    pub const SYNC: &str = "\u{E094}";
    pub const DOWNLOAD: &str = "\u{E20C}";
    pub const BOOK: &str = "\u{E0E6}";
    pub const PALETTE: &str = "\u{E6C8}";
    pub const PIN: &str = "\u{E3E2}";
    pub const GLOBE: &str = "\u{E288}";
    pub const BROADCAST: &str = "\u{E0F2}";
    pub const CARET_UP: &str = "\u{E13C}";
    pub const CARET_DOWN: &str = "\u{E136}";
    pub const TOOLS: &str = "\u{E270}";
    pub const SNIPPETS: &str = "\u{EAE8}";
}

/// Installs fonts, visuals and spacing. Call once from the app constructor.
pub fn apply(ctx: &Context) {
    install_fonts(ctx);
    apply_visuals(ctx);
}

fn install_fonts(ctx: &Context) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "phosphor".to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../assets/fonts/Phosphor.ttf"
        ))),
    );

    // Segoe UI is the native Windows 11 UI font; fall back silently to egui's default.
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let segoe = std::path::Path::new(&windir)
        .join("Fonts")
        .join("segoeui.ttf");
    let proportional = fonts.families.entry(FontFamily::Proportional).or_default();
    if let Ok(bytes) = std::fs::read(&segoe) {
        fonts
            .font_data
            .insert("segoe-ui".to_owned(), Arc::new(FontData::from_owned(bytes)));
        proportional.insert(0, "segoe-ui".to_owned());
    }
    proportional.push("phosphor".to_owned());

    ctx.set_fonts(fonts);
}

fn apply_visuals(ctx: &Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = Color32::from_rgb(18, 22, 29);
    visuals.panel_fill = PANEL_BG;
    visuals.faint_bg_color = SURFACE;
    visuals.extreme_bg_color = Color32::from_rgb(11, 14, 20);
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.hyperlink_color = ACCENT;
    visuals.selection.bg_fill = Color32::from_rgb(31, 75, 145);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);

    let radius = CornerRadius::same(RADIUS);
    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.menu_corner_radius = CornerRadius::same(8);

    let w = &mut visuals.widgets;
    w.noninteractive.bg_fill = Color32::from_rgb(18, 22, 29);
    w.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(38, 44, 54));
    // Inactive buttons: borderless until hovered, a flatter and more modern look.
    w.inactive.bg_fill = SURFACE;
    w.inactive.weak_bg_fill = SURFACE;
    w.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(38, 44, 54));
    w.hovered.bg_fill = SURFACE_HOVER;
    w.hovered.weak_bg_fill = SURFACE_HOVER;
    w.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    w.active.bg_fill = SURFACE_ACTIVE;
    w.active.weak_bg_fill = SURFACE_ACTIVE;
    w.active.bg_stroke = Stroke::new(1.0, ACCENT);
    w.open.bg_fill = SURFACE_ACTIVE;
    w.open.weak_bg_fill = SURFACE_ACTIVE;
    for state in [
        &mut w.noninteractive,
        &mut w.inactive,
        &mut w.hovered,
        &mut w.active,
        &mut w.open,
    ] {
        state.corner_radius = radius;
    }
    ctx.set_visuals(visuals);

    ctx.global_style_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(10.0, 5.0);
        style.spacing.interact_size.y = 26.0;
        style.spacing.menu_margin = egui::Margin::same(6);
        style
            .text_styles
            .insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
        style.text_styles.insert(
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Heading,
            FontId::new(22.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Small,
            FontId::new(11.5, FontFamily::Proportional),
        );
    });
}

/// Label combining a Phosphor glyph and text, e.g. `icon_label(icons::KEY, "Keys")`.
pub fn icon_label(icon: &str, text: &str) -> String {
    format!("{icon}  {text}")
}

/// Standard toolbar button: icon + text, subtle by default.
pub fn tool_button(ui: &mut Ui, icon: &str, text: &str) -> Response {
    ui.button(icon_label(icon, text))
}

/// Primary call-to-action button (filled with the accent color).
pub fn primary_button(ui: &mut Ui, icon: &str, text: &str) -> Response {
    ui.add(
        egui::Button::new(
            RichText::new(icon_label(icon, text))
                .strong()
                .color(Color32::WHITE),
        )
        .fill(ACCENT_STRONG)
        .stroke(Stroke::new(1.0, ACCENT)),
    )
}
