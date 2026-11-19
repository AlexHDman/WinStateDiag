use super::{Canvas, display, line_height, safe};
use crate::report_facts::{Facts, display_date, documents};
use powerlab_core::json::Json;
use std::collections::BTreeMap;

const W: i32 = 1055;
const A4_H: i32 = 1492;
const PAPER_MARGIN: i32 = 52;
const PAPER_BOTTOM: i32 = 1415;
const INK: u32 = 0x101f35;
const BLUE: u32 = 0x0758ac;
const DARK: u32 = 0x040e17;
const PANEL: u32 = 0x0c1d28;
const BORDER: u32 = 0x306367;
const CYAN: u32 = 0x58e3dc;
const WHITE: u32 = 0xecf5fa;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Attention,
    Critical,
    Info,
    Unknown,
}

impl Status {
    fn from_code(code: &str) -> Self {
        match code {
            "OK" | "PASS" | "CLEAN" | "NO_FINDINGS" => Self::Ok,
            "CRITICAL" => Self::Critical,
            "ATTENTION" | "WARNING" | "WARN" | "ERROR" | "FAILED" | "REPAIRED"
            | "PROBLEMS_FOUND" => Self::Attention,
            "INFO" | "HISTORICAL" => Self::Info,
            code if code.starts_with("ATTENTION_") => Self::Attention,
            code if code.starts_with("CRITICAL_") => Self::Critical,
            _ => Self::Unknown,
        }
    }
    fn label(self, ru: bool) -> &'static str {
        match self {
            Self::Ok => local(ru, "В норме", "OK"),
            Self::Attention => local(ru, "Внимание", "Attention"),
            Self::Critical => local(ru, "Критично", "Critical"),
            Self::Info => local(ru, "Сведения", "Information"),
            Self::Unknown => local(ru, "Нет результата", "Unavailable"),
        }
    }
    fn color(self, dark: bool) -> u32 {
        match (self, dark) {
            (Self::Ok, true) => 0x91d768,
            (Self::Attention, true) => 0xffbc53,
            (Self::Critical, true) => 0xff817b,
            (Self::Info, true) => CYAN,
            (Self::Unknown, true) => 0xa2b4c4,
            (Self::Ok, false) => 0x18783e,
            (Self::Attention, false) => 0x855200,
            (Self::Critical, false) => 0xa52630,
            (Self::Info, false) => BLUE,
            (Self::Unknown, false) => 0x47596b,
        }
    }
    fn mark(self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Attention => "!",
            Self::Critical => "×",
            Self::Info => "i",
            Self::Unknown => "—",
        }
    }
}

#[derive(Debug)]
struct Metric {
    name: &'static str,
    status: Status,
    detail: String,
}

pub(super) struct Report {
    ru: bool,
    computer: String,
    client: String,
    date: String,
    version: String,
    configuration: String,
    storage: String,
    findings: String,
    repairs: String,
    recommendations: String,
    summary: String,
    summary_title: &'static str,
    status: Status,
    metrics: Vec<Metric>,
}

fn local(ru: bool, a: &'static str, b: &'static str) -> &'static str {
    if ru { a } else { b }
}

fn string<'a>(j: &'a Json, key: &str) -> &'a str {
    j.get(key).and_then(Json::as_str).unwrap_or("")
}

fn bounded(s: &str, max: usize) -> String {
    // This is a client summary. The ZIP retains exact source evidence.
    let mut chars = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'));
    let mut output: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        output.push('…');
    }
    output
}

impl Report {
    pub(super) fn new(
        f: &Facts,
        raw: &str,
        summary: Option<&str>,
        advice: Option<&str>,
        ru: bool,
    ) -> Self {
        let mut assessment = None;
        let mut client = String::new();
        let mut checked = BTreeMap::new();
        for (source, doc) in documents(raw) {
            if source.eq_ignore_ascii_case("manifest.json") {
                client = doc
                    .get("session")
                    .map(|s| string(s, "client_name"))
                    .unwrap_or_default()
                    .to_owned();
            }
            if source.eq_ignore_ascii_case("State_Summary.json") {
                assessment = Some((
                    [
                        Status::from_code(string(&doc, "system")),
                        Status::from_code(string(&doc, "hardware")),
                        Status::from_code(string(&doc, "findings_status")),
                    ],
                    matches!(string(&doc, "coverage_status"), "COMPLETE" | "FULL"),
                ));
            }
            if let Some(checks) = doc.get("Checks").and_then(Json::as_array) {
                for item in checks {
                    let name = string(item, "Check");
                    let detail = string(item, "Detail");
                    let mut status = Status::from_code(string(item, "Status"));
                    if name == "CHKDSK"
                        && crate::deep_checks::chkdsk_finding(detail)
                            == Some(crate::deep_checks::ChkdskFinding::Repaired)
                    {
                        status = Status::Attention;
                    }
                    checked.insert(name.to_owned(), (status, bounded(&safe(detail), 220)));
                }
            }
        }
        let status = assessment.map_or(Status::Unknown, |(statuses, full)| {
            if statuses.contains(&Status::Critical) {
                Status::Critical
            } else if statuses.contains(&Status::Attention) {
                Status::Attention
            } else if full && statuses.contains(&Status::Ok) && !statuses.contains(&Status::Unknown)
            {
                Status::Ok
            } else {
                Status::Unknown
            }
        });
        let metrics = [
            ("WHEA", "WHEA", "WHEA"),
            ("Stability / BSOD", "BSOD", "BSOD"),
            ("SFC", "SFC", "SFC"),
            ("DISM", "DISM", "DISM"),
            ("CHKDSK", "CHKDSK", "CHKDSK"),
            ("Defender", "Defender", "Defender"),
            ("VSS services/providers", "Службы VSS", "VSS services"),
            ("VSS snapshot creation", "Снимок VSS", "VSS snapshot"),
            ("Storage", "Накопители", "Storage"),
        ]
        .into_iter()
        .map(|(key, a, b)| {
            let (status, detail) = checked
                .remove(key)
                .unwrap_or((Status::Unknown, String::new()));
            Metric {
                name: local(ru, a, b),
                status,
                detail: if detail.is_empty() {
                    local(ru, "В отчёте нет пояснения", "The archive gives no detail").into()
                } else {
                    detail
                },
            }
        })
        .collect();
        let mut storage = display(&f.disks);
        for change in f.changes.iter().take(6) {
            use std::fmt::Write;
            let unit = if ru && change.unit == "entries" {
                "записей"
            } else {
                &change.unit
            };
            let _ = write!(
                storage,
                "\n{} · {}: {} → {} {} · {} → {}",
                safe(&change.device),
                safe(&change.metric),
                change.before,
                change.after,
                unit,
                display_date(&change.before_date),
                display_date(&change.after_date)
            );
        }
        let mut findings = f
            .findings
            .iter()
            .take(8)
            .map(|item| {
                format!(
                    "• {} · {}",
                    display_date(&item.when),
                    bounded(&safe(&item.title), 220)
                )
            })
            .collect::<Vec<_>>();
        if f.findings.len() > findings.len() {
            findings.push(
                local(
                    ru,
                    "Дополнительные события сохранены в ZIP.",
                    "Additional findings are in the ZIP.",
                )
                .into(),
            );
        }
        if findings.is_empty() {
            findings.push(
                local(
                    ru,
                    "Замечания в извлечённых материалах отсутствуют.",
                    "No findings were extracted.",
                )
                .into(),
            );
        }
        let mut work = f
            .repairs
            .iter()
            .take(8)
            .map(|s| format!("• {}", bounded(&safe(s), 160)))
            .collect::<Vec<_>>();
        if f.repairs.len() > work.len() {
            work.push(
                local(
                    ru,
                    "Остальные записи сохранены в ZIP.",
                    "Additional entries are in the ZIP.",
                )
                .into(),
            );
        }
        if work.is_empty() {
            work.push(
                local(
                    ru,
                    "Выполненные ремонтные работы не подтверждены.",
                    "No repair work is verified.",
                )
                .into(),
            );
        }
        let configuration = format!(
            "{} · {}\n{} · {}\n{} · {}",
            display(&f.cpu),
            display(&f.ram),
            display(&f.board),
            display(&f.gpu),
            display(&f.windows),
            display(&f.bios)
        );
        let advice = advice.filter(|s| !s.trim().is_empty());
        let recommendations = advice.map(safe).unwrap_or_else(|| {
            let lines = f
                .findings
                .iter()
                .map(|f| f.check.as_str())
                .filter(|s| !s.is_empty())
                .collect::<std::collections::BTreeSet<_>>();
            if lines.is_empty() {
                local(
                    ru,
                    "Сверь результаты и ограничения в исходном отчёте.",
                    "Review the source report and its coverage.",
                )
                .into()
            } else {
                lines
                    .into_iter()
                    .take(8)
                    .map(|s| format!("• {}", safe(s)))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        });
        let summary = summary.filter(|s| !s.trim().is_empty());
        Self {
            ru,
            computer: bounded(&display(&f.computer), 120),
            client: bounded(&safe(&client), 120),
            date: display_date(&f.date),
            version: bounded(&display(&f.version), 30),
            configuration: bounded(&configuration, 750),
            storage: bounded(&storage, 1200),
            findings: findings.join("\n"),
            repairs: work.join("\n"),
            recommendations: bounded(&recommendations, 1600),
            summary: summary.map(|s| bounded(&safe(s), 1800)).unwrap_or_else(|| {
                local(ru, "Состояние и рекомендации отражают материалы выбранной диагностики. Подробности и границы проверки сохранены в ZIP.",
                    "The assessment and next steps reflect the selected diagnostic archive. Evidence and coverage are in the ZIP.").into()
            }),
            summary_title: if summary.is_some() { local(ru, "Заключение ИИ", "AI conclusion") }
                else { local(ru, "Сводка диагностики", "Diagnostic summary") },
            status,
            metrics,
        }
    }
    fn heading(&self) -> &'static str {
        local(self.ru, "ОТЧЁТ ДИАГНОСТИКИ", "DIAGNOSTIC REPORT")
    }
    fn state(&self) -> &'static str {
        match self.status {
            Status::Ok => local(
                self.ru,
                "Проверенные показатели в норме",
                "Checked results are normal",
            ),
            Status::Attention => local(self.ru, "Требуется внимание", "Attention required"),
            Status::Critical => local(self.ru, "Критическое замечание", "Critical finding"),
            _ => local(self.ru, "Проверка с ограничениями", "Coverage is limited"),
        }
    }
    fn identity(&self) -> String {
        if self.client.is_empty() {
            self.computer.clone()
        } else {
            format!("{} / {}", self.client, self.computer)
        }
    }
    fn sections(&self) -> [(&'static str, &str); 6] {
        [
            (
                local(self.ru, "Накопители и динамика", "Storage and changes"),
                &self.storage,
            ),
            (local(self.ru, "Замечания", "Findings"), &self.findings),
            (
                local(self.ru, "Конфигурация", "Configuration"),
                &self.configuration,
            ),
            (
                local(self.ru, "Подтверждённые работы", "Verified work"),
                &self.repairs,
            ),
            (
                local(self.ru, "Рекомендации", "Next steps"),
                &self.recommendations,
            ),
            (self.summary_title, &self.summary),
        ]
    }
}

fn shield(c: &mut Canvas, x: i32, y: i32, tone: Status) {
    let color = tone.color(true);
    let points = [
        [x + 45, y],
        [x + 85, y + 17],
        [x + 81, y + 63],
        [x + 67, y + 83],
        [x + 45, y + 100],
        [x + 23, y + 83],
        [x + 9, y + 63],
        [x + 5, y + 17],
        [x + 45, y],
    ];
    c.stroke(&points, 3, color);
    let mark = if tone == Status::Ok {
        "✓"
    } else {
        tone.mark()
    };
    c.text(mark, [x + 28, y + 22, 57, 60], 45, color, true);
}

fn band(c: &mut Canvas, report: &Report, x: i32, y: i32, width: i32) {
    c.panel([x, y, width, 151], BORDER, PANEL);
    shield(c, x + 30, y + 25, report.status);
    c.text(
        local(report.ru, "Общее состояние", "Overall state"),
        [x + 151, y + 19, width - 181, 39],
        29,
        WHITE,
        true,
    );
    let status = c.lines(report.state(), width - 181, 44, true);
    c.draw_lines(
        &status,
        [x + 151, y + 68, width - 181],
        44,
        report.status.color(true),
        true,
    );
}

fn dark_section(
    c: &mut Canvas,
    title: &str,
    text: &str,
    [x, y, w, height]: [i32; 4],
    border: u32,
) -> i32 {
    let headings = c.lines(title, w - 48, 28, true);
    let lines = c.lines(text, w - 48, 24, false);
    let head = headings.len() as i32 * line_height(28);
    let height = height.max(head + lines.len() as i32 * line_height(24) + 54);
    c.panel([x, y, w, height], border, PANEL);
    c.draw_lines(&headings, [x + 24, y + 15, w - 48], 28, CYAN, true);
    c.draw_lines(&lines, [x + 24, y + 25 + head, w - 48], 24, WHITE, false);
    height
}

pub(super) fn render_dark(report: &Report) -> Result<Canvas, String> {
    // Measure and paint through the same DC. The final encoded raster is cropped
    // to the bottom of the footer.
    let mut c = Canvas::new(W, 5900, 1, DARK)?;
    c.logo(42, 27, 278);
    c.fill(334, 28, 1, 106, 0x926729);
    c.text(report.heading(), [365, 29, 646, 65], 44, WHITE, true);
    let names = c.lines(&report.identity(), 646, 28, true);
    let bottom = c.draw_lines(&names, [365, 91, 646], 28, CYAN, true) + 91;
    c.text(
        &report.date,
        [365, bottom + 1, 646, 33],
        22,
        0xb2c4d1,
        false,
    );
    let mut y = (bottom + 52).max(167);
    band(&mut c, report, 42, y, W - 84);
    y += 174;
    c.text(
        local(report.ru, "КЛЮЧЕВЫЕ ПОКАЗАТЕЛИ", "KEY RESULTS"),
        [56, y, 943, 44],
        29,
        WHITE,
        true,
    );
    y += 52;
    let tile_w = 313;
    for row in report.metrics.chunks(3) {
        let details = row
            .iter()
            .map(|item| c.lines(&item.detail, tile_w - 30, 19, false))
            .collect::<Vec<_>>();
        let height = 95 + details.iter().map(Vec::len).max().unwrap_or(0) as i32 * line_height(19);
        for (i, (item, lines)) in row.iter().zip(details).enumerate() {
            let x = 42 + i as i32 * (tile_w + 16);
            c.panel([x, y, tile_w, height], BORDER, PANEL);
            let color = item.status.color(true);
            c.text(
                item.status.mark(),
                [x + 14, y + 10, 35, 44],
                28,
                color,
                true,
            );
            c.text(
                item.name,
                [x + 54, y + 10, tile_w - 66, 34],
                23,
                WHITE,
                true,
            );
            c.text(
                item.status.label(report.ru),
                [x + 54, y + 45, tile_w - 66, 32],
                21,
                color,
                false,
            );
            c.draw_lines(&lines, [x + 15, y + 81, tile_w - 30], 19, WHITE, false);
        }
        y += height + 13;
    }
    y += 8;
    let sections = report.sections();
    let slim = 475;
    for (row, pair) in sections[..4].as_chunks::<2>().0.iter().enumerate() {
        let height = pair
            .iter()
            .map(|(title, body)| {
                c.lines(title, slim - 48, 28, true).len() as i32 * line_height(28)
                    + c.lines(body, slim - 48, 24, false).len() as i32 * line_height(24)
                    + 54
            })
            .max()
            .unwrap_or(0);
        dark_section(&mut c, pair[0].0, pair[0].1, [42, y, slim, height], BORDER);
        let border = if row == 0 && report.status == Status::Attention {
            0x895d24
        } else {
            BORDER
        };
        dark_section(
            &mut c,
            pair[1].0,
            pair[1].1,
            [42 + slim + 21, y, slim, height],
            border,
        );
        y += height + 18;
    }
    for (title, body) in &sections[4..] {
        y += dark_section(&mut c, title, body, [42, y, W - 84, 0], BORDER) + 18;
    }
    c.fill(42, y + 8, W - 84, 1, 0x9c702a);
    c.text(
        &format!("EXPC · WinDiag {} · {}", report.version, report.date),
        [42, y + 25, W - 84, 35],
        21,
        0xe7c473,
        false,
    );
    y += 80;
    if y > c.h as i32 {
        return Err(local(
            report.ru,
            "Текст постера слишком длинный. Уточни состав отчёта.",
            "The poster content is too long.",
        )
        .into());
    }
    c.panel_edges([12, 12, W - 24, y - 24], 0x35656a);
    c.h = y as usize;
    Ok(c)
}

struct LightPages<'a> {
    pages: Vec<Canvas>,
    page: Canvas,
    y: i32,
    report: &'a Report,
}

impl<'a> LightPages<'a> {
    fn new(report: &'a Report) -> Result<Self, String> {
        let mut page = Self::blank()?;
        page.fill(PAPER_MARGIN, 52, 7, 243, 0x108cf1);
        // The approved mark is readable on the same dark brand strip in print.
        page.fill(69, 52, 335, 113, 0x081624);
        page.logo(86, 58, 290);
        page.text(
            local(report.ru, "ОТЧЁТ", "REPORT"),
            [70, 174, 466, 67],
            52,
            INK,
            true,
        );
        let title = page.lines(
            local(
                report.ru,
                "О ТЕХНИЧЕСКОМ СОСТОЯНИИ КОМПЬЮТЕРА",
                "COMPUTER SERVICE REPORT",
            ),
            466,
            25,
            true,
        );
        let title_bottom = 236 + page.draw_lines(&title, [70, 236, 466], 25, INK, true);
        page.fill(536, 52, 467, 33, BLUE);
        page.text(
            local(
                report.ru,
                "ТЕХНИЧЕСКАЯ ДИАГНОСТИКА",
                "TECHNICAL DIAGNOSTICS",
            ),
            [550, 55, 438, 32],
            21,
            0xffffff,
            true,
        );
        let rows = [
            format!("{} · {}", local(report.ru, "Дата", "Date"), report.date),
            format!(
                "{} · {}",
                local(report.ru, "Компьютер", "Computer"),
                report.computer
            ),
            format!(
                "{} · {}",
                local(report.ru, "Клиент", "Client"),
                display(&report.client)
            ),
        ];
        let mut y = 101;
        for row in rows {
            let lines = page.lines(&row, 440, 23, false);
            y += page.draw_lines(&lines, [549, y, 440], 23, INK, false) + 7;
            page.fill(548, y, 440, 1, 0xc9d8e8);
            y += 8;
        }
        y = y.max(title_bottom).max(280) + 20;
        band(&mut page, report, PAPER_MARGIN, y, W - 2 * PAPER_MARGIN);
        Ok(Self {
            pages: Vec::new(),
            page,
            y: y + 171,
            report,
        })
    }
    fn blank() -> Result<Canvas, String> {
        Canvas::new(W, A4_H, 2, 0xffffff)
    }
    fn finish_footer(&mut self) {
        self.page
            .fill(PAPER_MARGIN, 1431, W - 2 * PAPER_MARGIN, 1, 0xb8cddd);
        self.page.text(
            &format!(
                "EXPC · WinDiag {} · {}    |    {} {}",
                self.report.version,
                self.report.date,
                local(self.report.ru, "Страница", "Page"),
                self.pages.len() + 1
            ),
            [PAPER_MARGIN, 1441, W - 2 * PAPER_MARGIN, 38],
            19,
            INK,
            false,
        );
    }
    fn next_page(&mut self) -> Result<(), String> {
        if self.pages.len() >= 7 {
            return Err(local(
                self.report.ru,
                "Отчёт превышает восемь страниц.",
                "Report exceeds eight pages.",
            )
            .into());
        }
        self.finish_footer();
        self.pages
            .push(std::mem::replace(&mut self.page, Self::blank()?));
        self.page
            .fill(PAPER_MARGIN, 49, W - 2 * PAPER_MARGIN, 54, BLUE);
        self.page.text(
            self.report.heading(),
            [PAPER_MARGIN + 14, 58, W - 2 * PAPER_MARGIN - 28, 42],
            28,
            0xffffff,
            true,
        );
        let lines = self
            .page
            .lines(&self.report.identity(), W - 2 * PAPER_MARGIN, 23, false);
        self.y =
            115 + self.page.draw_lines(
                &lines,
                [PAPER_MARGIN, 111, W - 2 * PAPER_MARGIN],
                23,
                INK,
                false,
            ) + 16;
        Ok(())
    }
    fn table_header(&mut self) {
        self.page
            .fill(PAPER_MARGIN, self.y, W - 2 * PAPER_MARGIN, 42, 0xe8f2fc);
        for (i, title) in [
            local(self.report.ru, "ПРОВЕРЕНО", "CHECKED"),
            local(self.report.ru, "СОСТОЯНИЕ", "STATE"),
            local(
                self.report.ru,
                "ПОКАЗАТЕЛЬ / КОММЕНТАРИЙ",
                "METRIC / COMMENT",
            ),
        ]
        .iter()
        .enumerate()
        {
            self.page.text(
                title,
                [[64, 340, 571][i], self.y + 6, [252, 207, 420][i], 33],
                20,
                INK,
                true,
            );
        }
        self.y += 43;
    }
    fn metric(&mut self, item: &Metric) -> Result<(), String> {
        let name = self.page.lines(item.name, 245, 22, true);
        let state = self
            .page
            .lines(item.status.label(self.report.ru), 173, 21, true);
        let detail = self.page.lines(&item.detail, 413, 21, false);
        let height =
            (name.len().max(state.len()).max(detail.len()) as i32 * line_height(22) + 12).max(45);
        if self.y + height > PAPER_BOTTOM {
            self.next_page()?;
            self.table_header();
        }
        self.page.panel(
            [PAPER_MARGIN, self.y, W - 2 * PAPER_MARGIN, height],
            0xd7e0ea,
            0xf9fbff,
        );
        self.page.fill(327, self.y, 1, height, 0xd7e0ea);
        self.page.fill(558, self.y, 1, height, 0xd7e0ea);
        self.page
            .draw_lines(&name, [64, self.y + 6, 245], 22, INK, true);
        self.page.text(
            item.status.mark(),
            [341, self.y + 5, 24, 32],
            22,
            item.status.color(false),
            true,
        );
        self.page.draw_lines(
            &state,
            [372, self.y + 6, 173],
            21,
            item.status.color(false),
            true,
        );
        self.page
            .draw_lines(&detail, [571, self.y + 6, 413], 21, INK, false);
        self.y += height - 1;
        Ok(())
    }
    fn section(&mut self, title: &str, body: &str) -> Result<(), String> {
        let width = W - 2 * PAPER_MARGIN;
        let lines = self.page.lines(body, width - 28, 22, false);
        let line = line_height(22);
        let mut from = 0;
        while from < lines.len() {
            if self.y + 58 + line > PAPER_BOTTOM {
                self.next_page()?;
            }
            let count = ((PAPER_BOTTOM - self.y - 58) / line).max(1) as usize;
            let end = (from + count).min(lines.len());
            self.page.fill(PAPER_MARGIN, self.y, width, 34, BLUE);
            let heading = if from == 0 {
                title.to_owned()
            } else {
                format!(
                    "{title} · {}",
                    local(self.report.ru, "продолжение", "continued")
                )
            };
            self.page.text(
                &heading,
                [PAPER_MARGIN + 13, self.y + 3, width - 26, 33],
                23,
                0xffffff,
                true,
            );
            let used = self.page.draw_lines(
                &lines[from..end],
                [PAPER_MARGIN + 14, self.y + 41, width - 28],
                22,
                INK,
                false,
            );
            self.y += used + 57;
            from = end;
        }
        Ok(())
    }
}

pub(super) fn render_light(report: &Report) -> Result<Vec<Canvas>, String> {
    let mut book = LightPages::new(report)?;
    book.table_header();
    for metric in &report.metrics {
        book.metric(metric)?;
    }
    book.y += 17;
    for (title, body) in report.sections() {
        book.section(title, body)?;
    }
    book.finish_footer();
    book.pages.push(book.page);
    Ok(book.pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checks_show_recorded_status_and_long_content_spills() {
        let raw = r#"
========== State_Summary.json ==========
{"system":"ATTENTION_UNEXPECTED_SHUTDOWN","hardware":"OK","coverage_status":"LIMITED","findings_status":"ATTENTION"}
========== Checks.json ==========
{"Checks":[{"Check":"CHKDSK","Status":"SKIPPED","Detail":"Not run"},{"Check":"WHEA","Status":"OK","Detail":"Verified count 0"}]}
"#;
        let report = Report::new(
            &Facts {
                computer: "ТестоваяСтанция".repeat(12),
                ram: "DDR4 64 ГБ".into(),
                ..Default::default()
            },
            raw,
            Some(&"Длинное пояснение о проверке и первичных материалах. ".repeat(36)),
            Some(&"Требуется дополнительная проверка состояния накопителя. ".repeat(26)),
            true,
        );
        assert_eq!(report.status, Status::Attention);
        assert!(
            report
                .metrics
                .iter()
                .any(|m| m.name == "CHKDSK" && m.status == Status::Unknown)
        );
        assert!(
            report
                .metrics
                .iter()
                .any(|m| m.name == "WHEA" && m.status == Status::Ok)
        );
        let pages = render_light(&report).unwrap();
        assert!(pages.len() > 1);
        assert!(pages.iter().all(|p| p.w == 2110 && p.h == 2984));
        assert!(render_dark(&report).unwrap().h > 1500);
    }
}
