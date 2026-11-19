//! Local build information and explicitly requested public release metadata.
use crate::{
    APP_VERSION, portable,
    ui::{dashboard::expc_header_logo, paint},
};
use egui::{Color32, RichText, Stroke, vec2};
use powerlab_core::json::Json;
use std::{
    io::Read,
    process::{Command, Stdio},
    sync::{atomic::AtomicBool, mpsc},
    time::Duration,
};

const BUILD_DATE: &str = env!("WSD_BUILD_DATE");
const RELEASES_PAGE: &str = "https://github.com/AlexHDman/WinStateDiag/releases";
const API: &str = "https://api.github.com/repos/AlexHDman/WinStateDiag/releases?per_page=20";
const CYAN: Color32 = Color32::from_rgb(51, 237, 243);
const WHITE: Color32 = Color32::from_rgb(238, 244, 255);
const MUTED: Color32 = Color32::from_rgb(193, 207, 237);

const CHANGES: &[(&str, &str, Color32, &str)] = &[
    (
        "Отчёт ИИ и разбор сетевых отказов",
        "AI report and clearer network errors",
        Color32::from_rgb(203, 134, 255),
        "AI",
    ),
    (
        "Два постера и предпросмотр печати A4",
        "Two posters and A4 print preview",
        CYAN,
        "A4",
    ),
    (
        "Компактная однофайловая поставка",
        "Smaller single-file distribution",
        Color32::from_rgb(255, 212, 95),
        "1",
    ),
];

#[derive(Debug, Default, PartialEq, Eq)]
enum Release {
    #[default]
    Unchecked,
    Checking,
    NoPublished,
    NoStable,
    Current(String),
    Available(String),
    Ahead(String),
    Error,
}

fn local(ru: bool, a: &'static str, b: &'static str) -> &'static str {
    if ru { a } else { b }
}

impl Release {
    fn text(&self, ru: bool) -> String {
        match self {
            Self::Unchecked => local(ru, "Ещё не проверено", "Not checked yet").into(),
            Self::Checking => local(ru, "Проверка…", "Checking…").into(),
            Self::NoPublished => {
                local(ru, "Нет опубликованных выпусков", "No published releases").into()
            }
            Self::NoStable => local(ru, "Нет стабильных выпусков", "No stable releases").into(),
            Self::Current(v) => format!("{} · {v}", local(ru, "Актуальная версия", "Up to date")),
            Self::Available(v) => format!(
                "{} · {v}",
                local(ru, "Доступно обновление", "Update available")
            ),
            Self::Ahead(v) => format!(
                "{} · {v}",
                local(
                    ru,
                    "Последний опубликованный выпуск",
                    "Latest published release"
                )
            ),
            Self::Error => local(
                ru,
                "Ошибка получения сведений с GitHub",
                "Could not check GitHub",
            )
            .into(),
        }
    }
}

fn version(s: &str) -> Option<[u32; 3]> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let pieces = s.split('.').collect::<Vec<_>>();
    if !(2..=3).contains(&pieces.len()) || s.len() > 30 {
        return None;
    }
    let mut nums = [0; 3];
    for (i, piece) in pieces.into_iter().enumerate() {
        if piece.is_empty() || !piece.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        nums[i] = piece.parse().ok()?;
    }
    Some(nums)
}

fn releases(response: &str, installed: &str) -> Release {
    let (Some(installed), Ok(Json::Array(items))) = (version(installed), Json::parse(response))
    else {
        return Release::Error;
    };
    let mut prerelease = false;
    let mut latest = None;
    for item in &items {
        match (item.get("draft"), item.get("prerelease")) {
            (Some(Json::Bool(true)), _) => continue,
            (Some(Json::Bool(false)), Some(Json::Bool(true))) => {
                prerelease = true;
                continue;
            }
            (Some(Json::Bool(false)), Some(Json::Bool(false))) => {}
            _ => return Release::Error,
        }
        let Some(tag) = item.get("tag_name").and_then(Json::as_str) else {
            return Release::Error;
        };
        let Some(parsed) = version(tag) else {
            return Release::Error;
        };
        if latest.is_none_or(|(previous, _)| parsed > previous) {
            latest = Some((parsed, tag));
        }
    }
    match latest {
        Some((latest, tag)) if latest > installed => Release::Available(tag.into()),
        Some((latest, tag)) if latest == installed => Release::Current(tag.into()),
        Some((_, tag)) => Release::Ahead(tag.into()),
        None if prerelease => Release::NoStable,
        None => Release::NoPublished,
    }
}

fn fetch() -> Release {
    let script = format!(
        "{}\n$url='{}'\n{}",
        crate::ps_exec::PS_PRELUDE,
        API,
        r#"
$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$request=[Net.HttpWebRequest]::Create([Uri]$url)
$request.AllowAutoRedirect=$false; $request.UseDefaultCredentials=$false
$request.Timeout=8000; $request.ReadWriteTimeout=8000
$request.UserAgent='EXPC-WinDiag'; $request.Accept='application/vnd.github+json'
$request.Headers['X-GitHub-Api-Version']='2022-11-28'
$res=$request.GetResponse()
try {
    if ([int]$res.StatusCode -ne 200) { throw 'GitHub request did not return 200' }
    $stream=$res.GetResponseStream(); $buf=New-Object byte[] 8192
    $output=[Console]::OpenStandardOutput(); $total=0
    try {
        while (($n=$stream.Read($buf,0,$buf.Length)) -gt 0) {
            $total+=$n
            if ($total -gt 524288) { throw 'GitHub response exceeds limit' }
            $output.Write($buf,0,$n)
        }
        $output.Flush()
    } finally { $stream.Dispose() }
} finally { $res.Dispose() }
"#
    );
    let mut cmd = Command::new("powershell.exe");
    cmd.env_remove("PSModulePath")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
        ])
        .arg(crate::ps_exec::encoded_command(&script))
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut guard) = crate::engine::ProcessGuard::spawn(cmd) else {
        return Release::Error;
    };
    let Some(out) = guard.child_mut().stdout.take() else {
        return Release::Error;
    };
    let read = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        out.take(524289).read_to_end(&mut bytes).ok()?;
        (bytes.len() <= 524288).then_some(bytes)
    });
    let result = guard.wait_or_cancel(&AtomicBool::new(false), Some(Duration::from_secs(12)));
    drop(guard);
    let body = read
        .join()
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    if result.is_ok_and(|s| s.success())
        && let Some(body) = body
    {
        releases(&body, APP_VERSION)
    } else {
        Release::Error
    }
}

#[derive(Default)]
pub struct AboutUi {
    pub open: bool,
    licenses: bool,
    release: Release,
    release_rx: Option<mpsc::Receiver<Release>>,
    license_rx: Option<mpsc::Receiver<Result<portable::Prepared, String>>>,
    prepared: Option<portable::Prepared>,
    message: String,
    selected: Option<&'static str>,
    text: String,
}

impl AboutUi {
    fn poll(&mut self, ctx: &egui::Context, ru: bool) {
        if let Some(rx) = self.release_rx.as_ref() {
            match rx.try_recv() {
                Ok(release) => {
                    self.release = release;
                    self.release_rx = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.release = Release::Error;
                    self.release_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(150))
                }
            }
        }
        if let Some(rx) = self.license_rx.as_ref() {
            match rx.try_recv() {
                Ok(result) => {
                    self.license_rx = None;
                    match result {
                        Ok(value) => self.prepared = Some(value),
                        Err(error) => self.message = error,
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.license_rx = None;
                    self.message = local(
                        ru,
                        "Подготовка лицензий прервана",
                        "License preparation interrupted",
                    )
                    .into();
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(150))
                }
            }
        }
    }

    pub fn show(&mut self, ctx: &egui::Context, ru: bool) {
        self.poll(ctx, ru);
        if !self.open {
            return;
        }
        let mut open = true;
        egui::Window::new(local(ru, "О программе", "About"))
            .id(egui::Id::new("about_windiag"))
            .open(&mut open)
            .default_size(vec2(672., 531.))
            .min_size(vec2(390., 330.))
            .collapsible(false)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(6, 15, 43))
                    .stroke(Stroke::new(1.2, Color32::from_rgb(24, 149, 237)))
                    .corner_radius(12)
                    .inner_margin(egui::Margin::same(18)),
            )
            .show(ctx, |ui| {
                let actions_height = if ui.available_width() >= 590. {
                    56.
                } else {
                    106.
                };
                egui::ScrollArea::vertical()
                    .max_height((ui.available_height() - actions_height).max(154.))
                    .show(ui, |ui| {
                        self.content(ui, ru);
                        if self.licenses {
                            self.licensing(ui, ru);
                        }
                    });
                self.actions(ui, ru);
            });
        self.open = open;
    }

    fn information(&self, ru: bool) -> String {
        format!(
            "EXPC WinDiag {APP_VERSION}\n{}: {BUILD_DATE} UTC\nGitHub: {}",
            local(ru, "Дата сборки", "Build date"),
            self.release.text(ru)
        )
    }

    fn content(&mut self, ui: &mut egui::Ui, ru: bool) {
        let logo = expc_header_logo(ui.ctx());
        ui.horizontal_wrapped(|ui| {
            ui.image((logo.id(), vec2(205., 78.2)));
            ui.label(
                RichText::new("/")
                    .color(Color32::from_rgb(44, 124, 254))
                    .size(38.),
            );
            ui.label(RichText::new("WinDiag").strong().color(WHITE).size(44.));
            let (badge, _) = ui.allocate_exact_size(vec2(82., 44.), egui::Sense::hover());
            ui.painter()
                .rect_filled(badge, 9, Color32::from_rgb(131, 23, 237));
            ui.painter().text(
                badge.center(),
                egui::Align2::CENTER_CENTER,
                APP_VERSION,
                egui::FontId::proportional(29.),
                Color32::WHITE,
            );
            let (r, _) = ui.allocate_exact_size(vec2(97., 44.), egui::Sense::hover());
            paint::icon_pulse(ui.painter(), r, CYAN);
        });
        ui.label(
            RichText::new(local(
                ru,
                "Диагностика Windows и оборудования, мониторинг датчиков и отчёты для клиента.",
                "Windows and hardware diagnostics, sensor monitoring and client reports.",
            ))
            .size(22.)
            .color(WHITE),
        );
        ui.add_space(12.);
        egui::Frame::new()
            .fill(Color32::from_rgb(20, 36, 75))
            .stroke(Stroke::new(1., Color32::from_rgb(58, 92, 157)))
            .corner_radius(11)
            .inner_margin(13)
            .show(ui, |ui| {
                ui.set_min_width((ui.available_width() - 1.).max(200.));
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(local(ru, "Дата сборки", "Build date"))
                            .size(19.)
                            .color(MUTED),
                    );
                    let date = if ru {
                        crate::report_facts::display_date(BUILD_DATE)
                    } else {
                        BUILD_DATE.to_owned()
                    };
                    ui.label(
                        RichText::new(format!("{date} UTC"))
                            .strong()
                            .size(19.)
                            .color(WHITE),
                    );
                });
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(local(ru, "Выпуск на GitHub", "GitHub release"))
                            .size(19.)
                            .color(MUTED),
                    );
                    if matches!(self.release, Release::Checking) {
                        ui.spinner();
                    }
                    let text = self.release.text(ru);
                    if matches!(self.release, Release::Available(_)) {
                        ui.hyperlink_to(RichText::new(text).size(18.).color(CYAN), RELEASES_PAGE);
                    } else {
                        let color = if matches!(self.release, Release::Error) {
                            Color32::from_rgb(255, 184, 111)
                        } else {
                            WHITE
                        };
                        ui.label(RichText::new(text).size(18.).color(color));
                    }
                });
            });
        ui.add_space(11.);
        ui.label(
            RichText::new(format!(
                "{} {APP_VERSION}",
                local(ru, "Что нового в", "What's new in")
            ))
            .size(29.)
            .strong()
            .color(CYAN),
        );
        for &(a, b, tone, glyph) in CHANGES {
            ui.horizontal(|ui| {
                egui::Frame::new()
                    .stroke(Stroke::new(1.2, tone))
                    .corner_radius(5)
                    .inner_margin(egui::Margin::symmetric(4, 2))
                    .show(ui, |ui| {
                        ui.set_min_width(37.);
                        ui.label(RichText::new(glyph).size(16.).strong().color(tone));
                    });
                ui.label(RichText::new(local(ru, a, b)).size(20.).color(WHITE));
            });
            ui.add_space(5.);
        }
    }

    fn actions(&mut self, ui: &mut egui::Ui, ru: bool) {
        ui.add_space(12.);
        ui.horizontal_wrapped(|ui| {
            let update = egui::Button::new(
                RichText::new(local(ru, "↻  Обновление", "↻  Update"))
                    .size(19.)
                    .color(Color32::WHITE),
            )
            .min_size(vec2(176., 45.))
            .fill(Color32::from_rgb(5, 107, 225))
            .stroke(Stroke::new(1., CYAN))
            .corner_radius(9);
            if ui.add_enabled(self.release_rx.is_none(), update).clicked() {
                self.release = Release::Checking;
                let (tx, rx) = mpsc::channel();
                self.release_rx = Some(rx);
                #[cfg(not(test))]
                let task = fetch;
                #[cfg(test)]
                let task = || Release::NoPublished;
                std::thread::spawn(move || {
                    let _ = tx.send(task());
                });
                ui.ctx().request_repaint();
            }
            if action(ui, local(ru, "Скопировать сведения", "Copy details"), 236.).clicked()
            {
                ui.ctx().copy_text(self.information(ru));
            }
            if action(ui, local(ru, "Лицензии", "Licenses"), 141.).clicked() {
                self.licenses = !self.licenses;
                if self.licenses && self.prepared.is_none() && self.license_rx.is_none() {
                    let (tx, rx) = mpsc::channel();
                    self.license_rx = Some(rx);
                    #[cfg(not(test))]
                    std::thread::spawn(move || {
                        let _ = tx.send(portable::prepare());
                    });
                    #[cfg(test)]
                    let _ = tx.send(Err("Fixture".into()));
                }
            }
        });
    }

    fn licensing(&mut self, ui: &mut egui::Ui, ru: bool) {
        ui.separator();
        ui.label(if ru { portable::license_text() } else {
            "WinDiag / PowerLab — EXPC.\nLibreHardwareMonitorLib — MPL-2.0.\nPawnIO.Modules — LGPL-2.1-or-later. The original offline installer has separate upstream terms.\n.NET and Rust dependencies retain their notices and license files."
        });
        if self.license_rx.is_some() {
            ui.spinner();
        }
        if !self.message.is_empty() {
            ui.colored_label(Color32::YELLOW, &self.message);
        }
        if let Some(prepared) = &self.prepared {
            if ui
                .button(local(
                    ru,
                    "Открыть материалы лицензий",
                    "Open license materials",
                ))
                .clicked()
            {
                #[cfg(not(test))]
                let _ = std::process::Command::new("explorer.exe")
                    .arg(prepared.root.join("PowerLab/licenses"))
                    .spawn();
            }
            egui::ScrollArea::vertical()
                .max_height(175.)
                .id_salt("about_files")
                .show(ui, |ui| {
                    for (name, size) in portable::license_entries() {
                        if ui
                            .selectable_label(self.selected == Some(name), name)
                            .clicked()
                        {
                            self.selected = Some(name);
                            self.text = if size <= 2 * 1024 * 1024 && !name.ends_with(".zip") {
                                std::fs::read_to_string(prepared.root.join(name)).unwrap_or_else(
                                    |_| {
                                        local(
                                            ru,
                                            "Файл доступен в папке материалов.",
                                            "File available in the materials folder.",
                                        )
                                        .into()
                                    },
                                )
                            } else {
                                local(
                                    ru,
                                    "Архив доступен в папке материалов.",
                                    "Archive available in the materials folder.",
                                )
                                .into()
                            };
                        }
                    }
                });
            egui::ScrollArea::vertical()
                .max_height(215.)
                .id_salt("about_license")
                .show(ui, |ui| {
                    ui.label(&self.text);
                });
        }
    }
}

fn action(ui: &mut egui::Ui, title: &str, width: f32) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(title).size(18.).color(WHITE))
            .min_size(vec2(width, 45.))
            .fill(Color32::from_rgb(11, 26, 58))
            .stroke(Stroke::new(1., MUTED))
            .corner_radius(9),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Explicit public GitHub GET, no credentials or changes"]
    fn github_public_release_read() {
        let status = fetch();
        println!("GitHub public release status: {status:?}");
        assert_ne!(status, Release::Error);
    }
    #[test]
    fn github_state_requires_a_successful_public_release_listing() {
        let status = |tag| {
            releases(
                &format!(r#"[{{"draft":false,"prerelease":false,"tag_name":"{tag}"}}]"#),
                "1.12",
            )
        };
        assert_eq!(releases("[]", "1.12"), Release::NoPublished);
        assert_eq!(
            releases(
                r#"[{"draft":false,"prerelease":true,"tag_name":"v1.13-rc"}]"#,
                "1.12"
            ),
            Release::NoStable
        );
        assert_eq!(
            releases(r#"{"message":"Not Found"}"#, "1.12"),
            Release::Error
        );
        assert_eq!(releases("[{}]", "1.12"), Release::Error);
        assert!(matches!(status("v1.12"), Release::Current(_)));
        assert!(matches!(status("1.13"), Release::Available(_)));
        assert!(matches!(status("v1.2.11"), Release::Ahead(_)));
        assert_eq!(status("main"), Release::Error);
        for ru in [false, true] {
            assert_ne!(Release::Unchecked.text(ru), Release::NoPublished.text(ru));
            assert_ne!(Release::Error.text(ru), Release::NoPublished.text(ru));
        }
    }
}
