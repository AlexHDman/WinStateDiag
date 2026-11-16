//! Typography runtime: loads the system UI faces the visual master was drawn
//! with (Segoe UI family + Consolas) straight from the Windows font folder —
//! nothing is copied, installed or embedded, so the portable EXE stays
//! self-contained. When a face is missing, the named families fall back to
//! egui's built-in fonts, so a `FontFamily::Name` lookup can never panic.

use super::tokens::typography::{TextStyle, Weight};
use egui::{FontData, FontDefinitions, FontFamily, FontId};
use std::path::PathBuf;
use std::sync::Arc;

pub const FAMILY_SEMIBOLD: &str = "wsd-semibold";
pub const FAMILY_BOLD: &str = "wsd-bold";

/// Font files for the four roles. Override for offline/QA rendering with
/// `WSD_FONTS="regular;semibold;bold;mono"` (absolute paths).
pub struct FontSources {
    pub regular: PathBuf,
    pub semibold: PathBuf,
    pub bold: PathBuf,
    pub mono: PathBuf,
}

impl FontSources {
    pub fn resolve() -> Self {
        if let Ok(spec) = std::env::var("WSD_FONTS") {
            let parts: Vec<&str> = spec.split(';').collect();
            if parts.len() == 4 {
                return Self {
                    regular: parts[0].into(),
                    semibold: parts[1].into(),
                    bold: parts[2].into(),
                    mono: parts[3].into(),
                };
            }
        }
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
        let dir = PathBuf::from(windir).join("Fonts");
        Self {
            regular: dir.join("segoeui.ttf"),
            semibold: dir.join("seguisb.ttf"),
            bold: dir.join("segoeuib.ttf"),
            mono: dir.join("consola.ttf"),
        }
    }
}

/// Installs the WinStateDiag font set. Returns the number of faces loaded
/// (0..=4) for diagnostics; the UI renders either way.
pub fn install(ctx: &egui::Context) -> usize {
    let sources = FontSources::resolve();
    let mut defs = FontDefinitions::default();
    let default_prop = defs
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let default_mono = defs
        .families
        .get(&FontFamily::Monospace)
        .cloned()
        .unwrap_or_default();

    let mut loaded = 0;
    let mut load = |key: &str, path: &PathBuf| -> Option<String> {
        let bytes = std::fs::read(path).ok()?;
        defs.font_data
            .insert(key.to_owned(), Arc::new(FontData::from_owned(bytes)));
        loaded += 1;
        Some(key.to_owned())
    };
    let regular = load("wsd-regular", &sources.regular);
    let semibold = load("wsd-semibold-face", &sources.semibold);
    let bold = load("wsd-bold-face", &sources.bold);
    let mono = load("wsd-mono", &sources.mono);

    let chain = |primary: Option<String>, secondary: Option<String>, rest: &[String]| {
        let mut v: Vec<String> = Vec::new();
        v.extend(primary);
        v.extend(secondary);
        v.extend(rest.iter().cloned());
        v
    };
    defs.families.insert(
        FontFamily::Proportional,
        chain(regular.clone(), None, &default_prop),
    );
    defs.families.insert(
        FontFamily::Name(FAMILY_SEMIBOLD.into()),
        chain(semibold, regular.clone(), &default_prop),
    );
    defs.families.insert(
        FontFamily::Name(FAMILY_BOLD.into()),
        chain(bold, regular, &default_prop),
    );
    defs.families
        .insert(FontFamily::Monospace, chain(mono, None, &default_mono));
    ctx.set_fonts(defs);
    loaded
}

/// True once the WinStateDiag families are live in the context (fonts set
/// via `set_fonts` only take effect on the following pass).
pub fn ready(ctx: &egui::Context) -> bool {
    ctx.fonts(|f| {
        let fams = &f.definitions().families;
        fams.contains_key(&FontFamily::Name(FAMILY_SEMIBOLD.into()))
            && fams.contains_key(&FontFamily::Name(FAMILY_BOLD.into()))
    })
}

pub fn font(style: TextStyle) -> FontId {
    let family = match style.weight {
        Weight::Regular => FontFamily::Proportional,
        Weight::Semibold => FontFamily::Name(FAMILY_SEMIBOLD.into()),
        Weight::Bold => FontFamily::Name(FAMILY_BOLD.into()),
        Weight::Mono => FontFamily::Monospace,
    };
    FontId::new(style.size, family)
}
