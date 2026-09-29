//! Centralized bilingual UI text (v0.3.6 final UI/i18n pass).
//!
//! One [`Language`], one [`Dict`] per language, one [`t`] lookup — never
//! scattered `if language == ...` branches. Every static GUI string that
//! the approved bilingual pass calls out lives here as a typed field;
//! dynamic messages use the small formatting helpers below instead of
//! ad-hoc string building at the call site. Technical identifiers (JSON
//! keys, STABLE/ACCEPT/UNSTABLE, NVMe/SATA bus names, drive letters) stay
//! language-neutral by design — they are read by tooling and by the
//! CryptoPro/benchmark backends, never by a human choosing a language.

/// The two supported UI languages. `Copy` + persisted as a single byte so
/// switching is instant (no reallocation, no rebuild of the window) and
/// storing the preference is trivial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    Ru,
    En,
}

impl Language {
    pub fn toggle(self) -> Self {
        match self {
            Language::Ru => Language::En,
            Language::En => Language::Ru,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Language::Ru => "ru",
            Language::En => "en",
        }
    }

    fn from_code(s: &str) -> Option<Self> {
        match s.trim() {
            "ru" => Some(Language::Ru),
            "en" => Some(Language::En),
            _ => None,
        }
    }
}

/// Every translated static string used by the dashboard. Adding a new
/// user-visible label means adding one field here and filling both
/// [`RU`] and [`EN`] — the compiler then guarantees no language is missing
/// a string.
#[derive(Debug)]
pub struct Dict {
    // ---- Header ----
    pub app_title: &'static str,
    pub header_subtitle: &'static str,

    // ---- Client / Computer ----
    pub client_label: &'static str,
    pub computer_label: &'static str,

    // ---- CryptoPro ----
    pub crypto_checking: &'static str,
    pub crypto_hash: &'static str,
    pub crypto_no_hash: &'static str,
    pub crypto_not_installed: &'static str,
    pub crypto_check_error: &'static str,
    pub crypto_rehash_button: &'static str,

    // ---- EXPC Diagnostics card ----
    pub expc_title: &'static str,
    pub expc_mode_standard: &'static str,
    pub expc_mode_standard_desc: &'static str,
    pub expc_mode_deep: &'static str,
    pub expc_mode_deep_desc: &'static str,
    pub expc_mode_full: &'static str,
    pub expc_mode_full_desc: &'static str,

    // ---- Hardware Report ----
    pub hardware_title: &'static str,
    pub hardware_include_label: &'static str,
    pub hardware_subtitle: &'static str,
    pub hardware_view_button: &'static str,

    // ---- EXPC stages ----
    pub stages_title_prefix: &'static str,
    pub stage_short: [&'static str; 14],
    pub stage_description: [&'static str; 14],
    pub stage_running: &'static str,
    pub stage_waiting: &'static str,
    pub stage_skipped: &'static str,
    pub stage_error: &'static str,
    pub stage_more_suffix: &'static str,

    // ---- Driver Audit ----
    pub driver_title: &'static str,
    pub driver_details_button: &'static str,
    pub driver_running: &'static str,
    pub driver_readonly_note: &'static str,
    pub driver_unavailable: &'static str,
    pub driver_status_ok: &'static str,
    pub driver_status_warning: &'static str,
    pub driver_status_problem: &'static str,
    pub driver_more_suffix: &'static str,
    pub driver_na: &'static str,
    pub driver_no_problem_reason: &'static str,
    pub driver_device_label: &'static str,
    pub driver_driver_label: &'static str,
    /// Driver Audit category words (presentation of the audit's labels).
    pub driver_cat_chipset: &'static str,
    pub driver_cat_audio: &'static str,
    pub driver_cat_network: &'static str,
    pub driver_alert_problems_only_fmt: &'static str,
    pub driver_alert_problems_and_warnings_fmt: &'static str,
    pub driver_alert_problem_note: &'static str,
    pub driver_alert_warning_fmt: &'static str,
    pub driver_alert_warning_note: &'static str,
    pub driver_ok_line_fmt: &'static str,

    // ---- Result ----
    pub result_title: &'static str,
    pub result_idle: &'static str,
    pub result_idle_hint: &'static str,
    pub result_running: &'static str,
    pub result_running_hint: &'static str,
    pub result_ready: &'static str,
    pub result_open_report_button: &'static str,
    pub result_open_folder_button: &'static str,
    pub result_failed: &'static str,
    pub stop_hover: &'static str,
    pub start_button: &'static str,
    pub start_running_button: &'static str,
    pub new_diagnostics_button: &'static str,

    // ---- Overall Progress ----
    pub overall_title: &'static str,
    pub overall_elapsed: &'static str,
    pub overall_eta: &'static str,
    pub overall_status_waiting: &'static str,
    pub overall_status_running: &'static str,
    pub overall_status_done: &'static str,
    pub overall_status_stopped: &'static str,
    pub overall_eta_calculating: &'static str,
    pub overall_modules_title: &'static str,
    pub module_status_waiting: &'static str,
    pub module_status_running: &'static str,
    pub module_status_done: &'static str,
    pub module_status_not_selected: &'static str,
    pub module_name_expc: &'static str,
    pub module_name_hardware: &'static str,
    pub module_name_zip: &'static str,

    // ---- Current Operation ----
    pub curop_title: &'static str,
    pub curop_waiting_name: &'static str,
    pub curop_waiting_subtitle: &'static str,
    pub curop_done_name: &'static str,
    pub curop_stopped_name: &'static str,
    pub curop_failed_name: &'static str,
    pub curop_stage_preparing: &'static str,
    pub curop_stage_packaging: &'static str,
    pub curop_stage_complete: &'static str,

    // ---- SSD / NVMe card ----
    pub ssd_title: &'static str,
    pub ssd_subtitle: &'static str,
    pub ssd_none_detected: &'static str,
    pub ssd_overflow_suffix: &'static str,
    /// A reserved SSD slot with no eligible SSD/NVMe in it.
    pub ssd_empty_slot: &'static str,
    /// Module name used in app-generated journal lines for the SSD test.
    pub ssd_module_name: &'static str,
    /// `{module} {path}`
    pub journal_module_added_fmt: &'static str,
    pub journal_ssd_target_unavailable: &'static str,
    /// `{disk}`
    pub journal_ssd_no_writable_fmt: &'static str,
    /// `{error}`
    pub journal_ssd_history_failed_fmt: &'static str,
    pub journal_diag_stopped_by_user: &'static str,
    pub ssd_info_title: &'static str,
    pub ssd_model_label: &'static str,
    pub ssd_capacity_label: &'static str,
    pub ssd_interface_label: &'static str,
    pub ssd_serial_label: &'static str,
    pub ssd_status_label: &'static str,
    pub ssd_serial_unreported: &'static str,
    pub ssd_state_ready: &'static str,
    pub ssd_state_running: &'static str,
    pub ssd_state_done: &'static str,
    pub ssd_state_no_target: &'static str,
    pub ssd_state_error: &'static str,
    pub ssd_state_cancelled: &'static str,
    pub ssd_state_unavailable: &'static str,
    pub ssd_temp_note_line1: &'static str,
    pub ssd_temp_note_line2: &'static str,
    pub ssd_start_button: &'static str,
    pub ssd_rerun_button: &'static str,
    pub ssd_details_button: &'static str,
    pub ssd_raw_passes_title: &'static str,
    pub driver_details_title: &'static str,
    // ---- Driver Audit popup body (v0.3.6 Visual Master alignment §11) ----
    pub driver_popup_running: &'static str,
    pub driver_popup_retry: &'static str,
    pub driver_popup_rerun: &'static str,
    /// `{status} {problems} {warnings} {ok} {devices} {days} {generated}`
    pub driver_popup_summary_fmt: &'static str,
    pub driver_popup_note: &'static str,
    /// `{device}`
    pub driver_popup_device_fmt: &'static str,
    /// `{provider} {date} {inf} {service}`
    pub driver_popup_provider_fmt: &'static str,
    /// `{event_id}`
    pub driver_popup_event_fmt: &'static str,
    /// `{last_seen}`
    pub driver_popup_last_seen_fmt: &'static str,
    pub driver_popup_unattributed_note: &'static str,
    /// `{error}`
    pub driver_popup_collection_error_fmt: &'static str,
    // ---- Hardware progress modal ----
    pub hw_progress_title: &'static str,
    pub hw_progress_collecting: &'static str,
    pub hw_progress_saving: &'static str,
    pub hw_progress_please_wait: &'static str,
    pub report_not_ready_error: &'static str,
    pub hw_journal_saved: &'static str,
    pub hw_journal_refreshed: &'static str,
    /// `{status} {problems} {warnings}`
    pub driver_journal_summary_fmt: &'static str,
    /// `{path}`
    pub driver_journal_added_fmt: &'static str,
    pub client_field_hint: &'static str,
    pub ssd_cancel_button: &'static str,
    pub ssd_elapsed_prefix: &'static str,
    pub ssd_preparing_file: &'static str,
    pub ssd_pass_word: &'static str,
    pub ssd_finishing: &'static str,
    pub ssd_profile_label: &'static str,
    pub ssd_passes_label: &'static str,
    pub ssd_duration_label: &'static str,
    pub ssd_read_spread_label: &'static str,
    pub ssd_write_spread_label: &'static str,
    pub ssd_stability_label: &'static str,

    // ---- Journal ----
    pub journal_title: &'static str,
    pub journal_clear_button: &'static str,
    pub journal_empty: &'static str,
    /// v0.3.7 full-journal viewer (Open button, window, Save/Copy/Close).
    pub journal_open_button: &'static str,
    pub journal_viewer_title: &'static str,
    pub journal_viewer_save: &'static str,
    pub journal_viewer_copy: &'static str,
    pub journal_viewer_close: &'static str,
    pub journal_viewer_saved: &'static str,
    pub journal_viewer_save_failed: &'static str,
    pub journal_viewer_copied: &'static str,
    /// `{count}` — lines dropped only past the session memory cap.
    pub journal_viewer_dropped_fmt: &'static str,
    /// v0.4.0 deep-check results: `[SFC, DISM, CHKDSK]` ×
    /// `[OK, ATTENTION, ERROR, UNKNOWN, SKIPPED]`.
    pub deep_check_findings: [[&'static str; 5]; 3],
    /// `{check}`, `{command}` — the command is shown as text only.
    pub deep_check_manual_command_fmt: &'static str,
    pub journal_report_finalized: &'static str,
    /// `{error}`
    pub journal_report_finalize_failed_fmt: &'static str,

    // ---- Application-generated status/journal strings ----
    pub status_ready: &'static str,
    pub status_diag_running: &'static str,
    pub status_diag_done: &'static str,
    pub status_diag_failed: &'static str,
    pub status_diag_stopped: &'static str,
    pub status_ssd_running: &'static str,
    pub journal_stopping: &'static str,
    pub journal_hw_already_open: &'static str,
}

pub static RU: Dict = Dict {
    app_title: "WinStateDiag",
    header_subtitle: "Диагностический центр состояния Windows",

    client_label: "Клиент",
    computer_label: "Компьютер",

    crypto_checking: "Проверка…",
    crypto_hash: "HASH",
    crypto_no_hash: "НЕТ HASH",
    crypto_not_installed: "НЕ УСТАНОВЛЕН",
    crypto_check_error: "ОШИБКА ПРОВЕРКИ",
    crypto_rehash_button: "Проверка",

    expc_title: "Диагностика ПК EXPC",
    expc_mode_standard: "Основная",
    expc_mode_standard_desc: "Стандартная проверка системы, журналов, устройств и служб.",
    expc_mode_deep: "Глубокие проверки...",
    expc_mode_deep_desc: "Выберите дополнительные глубокие проверки вручную.",
    expc_mode_full: "Полная",
    expc_mode_full_desc: "Все проверки, включая SFC / DISM / CHKDSK.",

    hardware_title: "Отчёт об оборудовании",
    hardware_include_label: "Отчёт об оборудовании",
    hardware_subtitle: "CPU, память, диски, GPU, сеть…",
    hardware_view_button: "Смотреть",

    stages_title_prefix: "EXPC — ЭТАПЫ ДИАГНОСТИКИ",
    stage_short: [
        "Сведения о системе",
        "Накопители и хранилище",
        "Устройства и драйверы",
        "События системы",
        "Теневые копии",
        "WHEA / CPER",
        "Выключения и BSOD",
        "Ошибки приложений",
        "Диагностика памяти",
        "Антивирус и Defender",
        "SFC /verifyonly",
        "DISM /ScanHealth",
        "CHKDSK /scan",
        "BIOS, драйверы, микропрограммы",
    ],
    stage_description: [
        "Сбор сведений о системе, железе, Windows и аптайме",
        "Накопители, свободное место и показатели надёжности",
        "Проблемные устройства Plug and Play",
        "Критические и ошибочные системные события за 14 дней",
        "Теневые копии (VSS) и события Volsnap",
        "WHEA / CPER за 30 дней — классификация по серьёзности",
        "Неожиданные выключения, Kernel-Power и BSOD за 30 дней",
        "Ошибки приложений за 14 дней",
        "Результаты Windows Memory Diagnostic",
        "Антивирус и состояние Microsoft Defender",
        "Проверка целостности системных файлов",
        "Диагностика хранилища компонентов",
        "Онлайн-проверка файловой системы",
        "BIOS, основные драйверы и микропрограммы — контроль версий",
    ],
    stage_running: "выполняется",
    stage_waiting: "Ожидание",
    stage_skipped: "Пропущено",
    stage_error: "Ошибка",
    stage_more_suffix: "— «Подробнее»",

    driver_title: "ПРОВЕРКА ДРАЙВЕРОВ",
    driver_details_button: "Подробнее",
    driver_running: "Проверка драйверов выполняется…",
    driver_readonly_note: "Только чтение: PnP, драйверы, журналы Windows.",
    driver_unavailable: "Проверка драйверов недоступна",
    driver_status_ok: "OK",
    driver_status_warning: "Внимание",
    driver_status_problem: "Проблема",
    driver_more_suffix: "с замечаниями",
    driver_na: "н/д",
    driver_no_problem_reason: "явных проблем не обнаружено",
    driver_device_label: "Устройство",
    driver_driver_label: "Драйвер",
    driver_cat_chipset: "Чипсет",
    driver_cat_audio: "Аудио",
    driver_cat_network: "Сеть",
    driver_alert_problems_only_fmt: "Обнаружены проблемные драйверы ({problems}).",
    driver_alert_problems_and_warnings_fmt: "Обнаружены проблемные драйверы ({problems}) и предупреждения ({warnings}).",
    driver_alert_problem_note: "Это может вызывать ошибки и нестабильную работу системы.",
    driver_alert_warning_fmt: "Есть предупреждения по драйверам ({warnings}).",
    driver_alert_warning_note: "Неисправность не подтверждена; подробности — «Подробнее» и отчёт.",
    driver_ok_line_fmt: "Явных проблем с драйверами не обнаружено (устройств: {devices}).",

    result_title: "РЕЗУЛЬТАТ",
    result_idle: "Диагностика не выполнялась.",
    result_idle_hint: "Запустите диагностику для создания отчёта.",
    result_running: "Диагностика выполняется…",
    result_running_hint: "Отчёт будет создан автоматически.",
    result_ready: "Отчёт готов",
    result_open_report_button: "Отчёт",
    result_open_folder_button: "Папка",
    result_failed: "Диагностика завершилась с ошибкой",
    stop_hover: "Остановить диагностику",
    start_button: "Запустить диагностику",
    start_running_button: "Выполняется…",
    new_diagnostics_button: "Новая диагностика",

    overall_title: "ОБЩИЙ ХОД ВЫПОЛНЕНИЯ",
    overall_elapsed: "Прошло",
    overall_eta: "Осталось (ETA)",
    overall_status_waiting: "Ожидание",
    overall_status_running: "Выполняется",
    overall_status_done: "Завершено",
    overall_status_stopped: "Остановлено",
    overall_eta_calculating: "рассчитывается…",
    overall_modules_title: "Модули диагностики",
    module_status_waiting: "Ожидание",
    module_status_running: "Выполняется",
    module_status_done: "Выполнено",
    module_status_not_selected: "Не выбран",
    module_name_expc: "Диагностика ПК EXPC",
    module_name_hardware: "Отчёт об оборудовании",
    module_name_zip: "ZIP-отчёт",

    curop_title: "Текущая операция",
    curop_waiting_name: "Ожидание запуска",
    curop_waiting_subtitle: "Выберите режим и нажмите «Запустить диагностику».",
    curop_done_name: "Диагностика завершена",
    curop_stopped_name: "Диагностика остановлена пользователем",
    curop_failed_name: "Ошибка диагностики",
    curop_stage_preparing: "Подготовка среды",
    curop_stage_packaging: "Сборка отчёта",
    curop_stage_complete: "Завершено",

    ssd_title: "Отчёт диагностики SSD / NVMe дисков",
    ssd_subtitle: "Выберите накопитель для тестирования:",
    ssd_none_detected: "Физические SSD/NVMe не обнаружены.",
    ssd_overflow_suffix: "ещё",
    ssd_empty_slot: "SSD не обнаружен",
    ssd_module_name: "Тест SSD",
    journal_module_added_fmt: "{module}: данные добавлены в отчёт сессии ({path}).",
    journal_ssd_target_unavailable: "[WARN] Выбранный накопитель недоступен для теста.",
    journal_ssd_no_writable_fmt: "[WARN] {disk}: нет доступного для записи тома на этом накопителе.",
    journal_ssd_history_failed_fmt: "[WARN] Не удалось сохранить историю теста SSD: {error}",
    journal_diag_stopped_by_user: "[INFO] Диагностика остановлена пользователем.",
    ssd_info_title: "Информация о выбранном диске",
    ssd_model_label: "Модель:",
    ssd_capacity_label: "Ёмкость:",
    ssd_interface_label: "Интерфейс:",
    ssd_serial_label: "Серийный №:",
    ssd_status_label: "Состояние:",
    ssd_serial_unreported: "Не сообщается",
    ssd_state_ready: "Готов к тесту",
    ssd_state_running: "Тест выполняется",
    ssd_state_done: "Тест завершён",
    ssd_state_no_target: "Нет доступного тома для теста",
    ssd_state_error: "Ошибка теста",
    ssd_state_cancelled: "Тест отменён",
    ssd_state_unavailable: "Недоступно",
    ssd_temp_note_line1: "Временный файл создаётся на выбранном",
    ssd_temp_note_line2: "накопителе и удаляется после завершения теста.",
    ssd_start_button: "Запустить тест",
    ssd_rerun_button: "Запустить повторно",
    ssd_details_button: "Детали",
    ssd_raw_passes_title: "Детали замера",
    driver_details_title: "Проверка драйверов — подробности",
    driver_popup_running: "Проверка выполняется…",
    driver_popup_retry: "Повторить проверку",
    driver_popup_rerun: "Проверить заново",
    driver_popup_summary_fmt: "Итог: {status} — проблем: {problems}, предупреждений: {warnings}, без замечаний: {ok}; устройств: {devices}; события за {days} дн.; {generated}",
    driver_popup_note: "Статус ставится только по конкретным признакам (ошибка PnP, сбой в модуле драйвера, Code Integrity, отказ загрузки). Возраст драйвера сам по себе не считается проблемой.",
    driver_popup_device_fmt: "Устройство: {device}",
    driver_popup_provider_fmt: "Поставщик драйвера: {provider}; дата: {date}; INF: {inf}; служба: {service}",
    driver_popup_event_fmt: ", событие {event_id}",
    driver_popup_last_seen_fmt: "  последнее: {last_seen}",
    driver_popup_unattributed_note: "События без привязки к текущим устройствам (на статус не влияют):",
    driver_popup_collection_error_fmt: "Ошибка сбора: {error}",
    hw_progress_title: "Диагностика оборудования",
    hw_progress_collecting: "Сбор информации об оборудовании…",
    hw_progress_saving: "Формирование отчёта…",
    hw_progress_please_wait: "Пожалуйста, подождите",
    report_not_ready_error: "Итоговый отчёт ещё не создан.",
    hw_journal_saved: "сохранён в отчёт сессии",
    hw_journal_refreshed: "обновлён в отчёте сессии",
    driver_journal_summary_fmt: "Проверка драйверов: {status} (проблем: {problems}, предупреждений: {warnings})",
    driver_journal_added_fmt: "Проверка драйверов: данные добавлены в отчёт сессии ({path}).",
    client_field_hint: "необязательно",
    ssd_cancel_button: "Отменить",
    ssd_elapsed_prefix: "Прошло:",
    ssd_preparing_file: "Подготовка временного файла",
    ssd_pass_word: "Проход",
    ssd_finishing: "Завершение",
    ssd_profile_label: "Профиль",
    ssd_passes_label: "Проходы",
    ssd_duration_label: "Длительность",
    ssd_read_spread_label: "Разброс чтения",
    ssd_write_spread_label: "Разброс записи",
    ssd_stability_label: "Стабильность",

    journal_title: "Журнал",
    journal_clear_button: "Очистить",
    journal_empty: "Журнал пуст.",
    journal_open_button: "Открыть",
    journal_viewer_title: "Журнал WinStateDiag",
    journal_viewer_save: "Сохранить",
    journal_viewer_copy: "Копировать",
    journal_viewer_close: "Закрыть",
    journal_viewer_saved: "Журнал сохранён",
    journal_viewer_save_failed: "Не удалось сохранить журнал",
    journal_viewer_copied: "Журнал скопирован в буфер обмена",
    journal_viewer_dropped_fmt: "Более ранние строки не сохранены (ограничение памяти): {count}",
    deep_check_findings: [
        [
            "SFC: нарушений целостности системных файлов не обнаружено.",
            "SFC: обнаружены нарушения целостности системных файлов Windows.",
            "SFC: проверку не удалось выполнить или её результат непригоден.",
            "SFC: результат проверки не удалось однозначно определить.",
            "SFC: проверка пропущена.",
        ],
        [
            "DISM: повреждений хранилища компонентов Windows не обнаружено.",
            "DISM: хранилище компонентов Windows требует восстановления.",
            "DISM: проверка завершилась ошибкой или хранилище компонентов не может быть восстановлено.",
            "DISM: результат проверки не удалось однозначно определить.",
            "DISM: проверка пропущена.",
        ],
        [
            "CHKDSK: проблем файловой системы не обнаружено.",
            "CHKDSK: обнаружены проблемы файловой системы, требующие внимания.",
            "CHKDSK: проверку не удалось выполнить.",
            "CHKDSK: результат проверки не удалось однозначно определить.",
            "CHKDSK: проверка пропущена.",
        ],
    ],
    deep_check_manual_command_fmt: "{check}: команда для ручного выполнения (WinStateDiag её не запускает): {command}",
    journal_report_finalized: "Отчёт проверен: в папке отчёта оставлен только итоговый ZIP.",
    journal_report_finalize_failed_fmt: "Файлы отчёта сохранены без очистки: {error}",

    status_ready: "Готов к работе",
    status_diag_running: "Выполняется диагностика…",
    status_diag_done: "Диагностика завершена",
    status_diag_failed: "Ошибка диагностики",
    status_diag_stopped: "Диагностика остановлена",
    status_ssd_running: "Выполняется тест SSD…",
    journal_stopping: "Остановка диагностики…",
    journal_hw_already_open: "Отчёт об оборудовании уже открыт.",
};

pub static EN: Dict = Dict {
    app_title: "WinStateDiag",
    header_subtitle: "Windows System Diagnostics Center",

    client_label: "Client",
    computer_label: "Computer",

    crypto_checking: "Checking…",
    crypto_hash: "HASH",
    crypto_no_hash: "NO HASH",
    crypto_not_installed: "NOT INSTALLED",
    crypto_check_error: "CHECK ERROR",
    crypto_rehash_button: "ReHash",

    expc_title: "EXPC PC Diagnostics",
    expc_mode_standard: "Standard",
    expc_mode_standard_desc: "Standard check of the system, logs, devices and services.",
    expc_mode_deep: "Deep checks...",
    expc_mode_deep_desc: "Choose additional deep checks manually.",
    expc_mode_full: "Full",
    expc_mode_full_desc: "All checks, including SFC / DISM / CHKDSK.",

    hardware_title: "Hardware Report",
    hardware_include_label: "Hardware Report",
    hardware_subtitle: "CPU, memory, drives, GPU, network…",
    hardware_view_button: "View",

    stages_title_prefix: "EXPC — DIAGNOSTIC STEPS",
    stage_short: [
        "System information",
        "Storage and drives",
        "Devices and drivers",
        "System events",
        "Shadow copies",
        "WHEA / CPER",
        "Shutdowns and BSOD",
        "Application errors",
        "Memory Diagnostic",
        "Antivirus and Defender",
        "SFC /verifyonly",
        "DISM /ScanHealth",
        "CHKDSK /scan",
        "BIOS, drivers, firmware",
    ],
    stage_description: [
        "Collects system, hardware, Windows and uptime information",
        "Drives, free space and reliability indicators",
        "Problem Plug and Play devices",
        "Critical and error System events over 14 days",
        "Shadow copies (VSS) and Volsnap events",
        "WHEA / CPER over 30 days — Severity classification",
        "Unexpected shutdowns, Kernel-Power and BSOD over 30 days",
        "Application errors over 14 days",
        "Windows Memory Diagnostic results",
        "Antivirus and Microsoft Defender status",
        "System file integrity check",
        "Component store diagnostics",
        "Online file system check",
        "BIOS, core drivers and firmware — version control",
    ],
    stage_running: "running",
    stage_waiting: "Waiting",
    stage_skipped: "Skipped",
    stage_error: "Error",
    stage_more_suffix: "— \"Details\"",

    driver_title: "DRIVER CHECK",
    driver_details_button: "Details",
    driver_running: "Driver check running…",
    driver_readonly_note: "Read-only: PnP, drivers, Windows logs.",
    driver_unavailable: "Driver check unavailable",
    driver_status_ok: "OK",
    driver_status_warning: "Warning",
    driver_status_problem: "Problem",
    driver_more_suffix: "flagged",
    driver_na: "N/A",
    driver_no_problem_reason: "no clear issues found",
    driver_device_label: "Device",
    driver_driver_label: "Driver",
    driver_cat_chipset: "Chipset",
    driver_cat_audio: "Audio",
    driver_cat_network: "Network",
    driver_alert_problems_only_fmt: "Problem drivers found ({problems}).",
    driver_alert_problems_and_warnings_fmt: "Problem drivers ({problems}) and warnings ({warnings}) found.",
    driver_alert_problem_note: "This can cause errors and an unstable system.",
    driver_alert_warning_fmt: "There are driver warnings ({warnings}).",
    driver_alert_warning_note: "Not confirmed as a fault; see \"Details\" and the report.",
    driver_ok_line_fmt: "No clear driver problems found (devices scanned: {devices}).",

    result_title: "RESULT",
    result_idle: "Diagnostics has not run yet.",
    result_idle_hint: "Run diagnostics to create a report.",
    result_running: "Diagnostics running…",
    result_running_hint: "The report will be created automatically.",
    result_ready: "Report ready",
    result_open_report_button: "Report",
    result_open_folder_button: "Folder",
    result_failed: "Diagnostics finished with an error",
    stop_hover: "Stop diagnostics",
    start_button: "Run Diagnostics",
    start_running_button: "Running…",
    new_diagnostics_button: "New Diagnostics",

    overall_title: "OVERALL PROGRESS",
    overall_elapsed: "Elapsed",
    overall_eta: "Remaining (ETA)",
    overall_status_waiting: "Waiting",
    overall_status_running: "Running",
    overall_status_done: "Completed",
    overall_status_stopped: "Stopped",
    overall_eta_calculating: "calculating…",
    overall_modules_title: "Diagnostic Modules",
    module_status_waiting: "Waiting",
    module_status_running: "Running",
    module_status_done: "Completed",
    module_status_not_selected: "Not selected",
    module_name_expc: "EXPC PC Diagnostics",
    module_name_hardware: "Hardware Report",
    module_name_zip: "ZIP Report",

    curop_title: "Current Operation",
    curop_waiting_name: "Waiting to start",
    curop_waiting_subtitle: "Choose a mode and click \"Run Diagnostics\".",
    curop_done_name: "Diagnostics completed",
    curop_stopped_name: "Diagnostics stopped by user",
    curop_failed_name: "Diagnostics error",
    curop_stage_preparing: "Preparing environment",
    curop_stage_packaging: "Building report",
    curop_stage_complete: "Completed",

    ssd_title: "SSD / NVMe Diagnostic Report",
    ssd_subtitle: "Select a drive to test:",
    ssd_none_detected: "No physical SSD/NVMe drives detected.",
    ssd_overflow_suffix: "more",
    ssd_empty_slot: "No SSD detected",
    ssd_module_name: "SSD benchmark",
    journal_module_added_fmt: "{module}: data added to the session report ({path}).",
    journal_ssd_target_unavailable: "[WARN] The selected drive is not available for the test.",
    journal_ssd_no_writable_fmt: "[WARN] {disk}: no writable volume on this drive.",
    journal_ssd_history_failed_fmt: "[WARN] Could not save the SSD test history: {error}",
    journal_diag_stopped_by_user: "[INFO] Diagnostics stopped by user.",
    ssd_info_title: "Selected Drive Information",
    ssd_model_label: "Model:",
    ssd_capacity_label: "Capacity:",
    ssd_interface_label: "Interface:",
    ssd_serial_label: "Serial No.:",
    ssd_status_label: "Status:",
    ssd_serial_unreported: "Not reported",
    ssd_state_ready: "Ready for test",
    ssd_state_running: "Test running",
    ssd_state_done: "Test completed",
    ssd_state_no_target: "No writable volume available",
    ssd_state_error: "Test error",
    ssd_state_cancelled: "Test cancelled",
    ssd_state_unavailable: "Unavailable",
    ssd_temp_note_line1: "A temporary file is created on the selected drive",
    ssd_temp_note_line2: "and removed after the test is completed.",
    ssd_start_button: "Run Test",
    ssd_rerun_button: "Run Test Again",
    ssd_details_button: "Details",
    ssd_raw_passes_title: "Benchmark Details",
    driver_details_title: "Driver Check — Details",
    driver_popup_running: "Check in progress…",
    driver_popup_retry: "Retry check",
    driver_popup_rerun: "Check again",
    driver_popup_summary_fmt: "Summary: {status} — problems: {problems}, warnings: {warnings}, no issues: {ok}; devices: {devices}; events over {days} days; {generated}",
    driver_popup_note: "Status is set only from specific signals (a PnP error, a driver-module crash, Code Integrity, a boot failure). Driver age alone is never treated as a problem.",
    driver_popup_device_fmt: "Device: {device}",
    driver_popup_provider_fmt: "Driver provider: {provider}; date: {date}; INF: {inf}; service: {service}",
    driver_popup_event_fmt: ", event {event_id}",
    driver_popup_last_seen_fmt: "  last seen: {last_seen}",
    driver_popup_unattributed_note: "Events not tied to a current device (do not affect status):",
    driver_popup_collection_error_fmt: "Collection error: {error}",
    hw_progress_title: "Hardware Diagnostics",
    hw_progress_collecting: "Collecting hardware information…",
    hw_progress_saving: "Generating the report…",
    hw_progress_please_wait: "Please wait",
    report_not_ready_error: "The final report has not been created yet.",
    hw_journal_saved: "saved to the session report",
    hw_journal_refreshed: "refreshed in the session report",
    driver_journal_summary_fmt: "Driver check: {status} (problems: {problems}, warnings: {warnings})",
    driver_journal_added_fmt: "Driver check: data added to the session report ({path}).",
    client_field_hint: "optional",
    ssd_cancel_button: "Cancel",
    ssd_elapsed_prefix: "Elapsed:",
    ssd_preparing_file: "Preparing the temporary file",
    ssd_pass_word: "Pass",
    ssd_finishing: "Finishing",
    ssd_profile_label: "Profile",
    ssd_passes_label: "Passes",
    ssd_duration_label: "Duration",
    ssd_read_spread_label: "Read spread",
    ssd_write_spread_label: "Write spread",
    ssd_stability_label: "Stability",

    journal_title: "Log",
    journal_clear_button: "Clear",
    journal_empty: "Log is empty.",
    journal_open_button: "Open",
    journal_viewer_title: "WinStateDiag Log",
    journal_viewer_save: "Save",
    journal_viewer_copy: "Copy",
    journal_viewer_close: "Close",
    journal_viewer_saved: "Log saved",
    journal_viewer_save_failed: "Failed to save log",
    journal_viewer_copied: "Log copied to clipboard",
    journal_viewer_dropped_fmt: "Earlier lines not kept (memory limit): {count}",
    deep_check_findings: [
        [
            "SFC: no system file integrity violations found.",
            "SFC: Windows system file integrity violations were found.",
            "SFC: the check could not complete or its result is unusable.",
            "SFC: the result could not be determined reliably.",
            "SFC: check skipped.",
        ],
        [
            "DISM: no component store corruption detected.",
            "DISM: the Windows component store is repairable.",
            "DISM: the scan failed or the component store cannot be repaired.",
            "DISM: the result could not be determined reliably.",
            "DISM: check skipped.",
        ],
        [
            "CHKDSK: no file system problems found.",
            "CHKDSK: file system problems requiring attention were found.",
            "CHKDSK: the check could not run.",
            "CHKDSK: the result could not be determined reliably.",
            "CHKDSK: check skipped.",
        ],
    ],
    deep_check_manual_command_fmt: "{check}: command for manual use (WinStateDiag does not run it): {command}",
    journal_report_finalized: "Report verified: only the final ZIP remains in the report folder.",
    journal_report_finalize_failed_fmt: "Report files kept without cleanup: {error}",

    status_ready: "Ready",
    status_diag_running: "Diagnostics running…",
    status_diag_done: "Diagnostics completed",
    status_diag_failed: "Diagnostics error",
    status_diag_stopped: "Diagnostics stopped",
    status_ssd_running: "Running SSD benchmark…",
    journal_stopping: "Stopping diagnostics…",
    journal_hw_already_open: "Hardware Report is already open.",
};

/// The one lookup point: every draw/build function calls `i18n::t(lang)`
/// and reads fields off the returned `&'static Dict` instead of branching
/// on `Language` itself.
pub fn t(lang: Language) -> &'static Dict {
    match lang {
        Language::Ru => &RU,
        Language::En => &EN,
    }
}

/// File the language preference is stored in, next to the portable EXE
/// (never the registry — the app must stay fully portable). Read/write
/// failures are always non-fatal: a missing or corrupt file just means
/// "use the default", never a startup error.
fn pref_path(exe_dir: &std::path::Path) -> std::path::PathBuf {
    exe_dir.join("WinStateDiag.lang")
}

/// Loads the last-selected language. Falls back to [`Language::Ru`] on any
/// I/O error, missing file, or unrecognized content — corrupted or
/// unreadable preference data must never block startup.
pub fn load(exe_dir: &std::path::Path) -> Language {
    std::fs::read_to_string(pref_path(exe_dir))
        .ok()
        .and_then(|s| Language::from_code(&s))
        .unwrap_or(Language::Ru)
}

/// Best-effort save; a read-only portable medium or a locked file must
/// never surface as an application error, so any failure is silently
/// ignored (the language simply won't persist for the next launch).
pub fn save(exe_dir: &std::path::Path, lang: Language) {
    let _ = std::fs::write(pref_path(exe_dir), lang.code());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_is_a_clean_swap() {
        assert_eq!(Language::Ru.toggle(), Language::En);
        assert_eq!(Language::En.toggle(), Language::Ru);
        assert_eq!(Language::Ru.toggle().toggle(), Language::Ru);
    }

    #[test]
    fn approved_russian_header_strings_match_exactly() {
        assert_eq!(RU.app_title, "WinStateDiag");
        assert_eq!(
            RU.header_subtitle,
            "Диагностический центр состояния Windows"
        );
    }

    #[test]
    fn approved_english_header_strings_match_exactly() {
        assert_eq!(EN.app_title, "WinStateDiag");
        assert_eq!(EN.header_subtitle, "Windows System Diagnostics Center");
    }

    #[test]
    fn approved_ssd_titles_match_exactly() {
        assert_eq!(RU.ssd_title, "Отчёт диагностики SSD / NVMe дисков");
        assert_eq!(EN.ssd_title, "SSD / NVMe Diagnostic Report");
        assert_eq!(RU.ssd_subtitle, "Выберите накопитель для тестирования:");
        assert_eq!(EN.ssd_subtitle, "Select a drive to test:");
    }

    #[test]
    fn details_button_never_mentions_raw_passes_in_either_language() {
        assert_eq!(RU.ssd_details_button, "Детали");
        assert_eq!(EN.ssd_details_button, "Details");
        assert!(!RU.ssd_details_button.to_lowercase().contains("raw"));
        assert!(!EN.ssd_details_button.to_lowercase().contains("raw"));
    }

    #[test]
    fn crypto_button_is_localized_but_stays_the_same_rehash_action() {
        assert_eq!(RU.crypto_rehash_button, "Проверка");
        assert_eq!(EN.crypto_rehash_button, "ReHash");
        // The status word itself is a plain technical "HASH" in both
        // languages, never redundant "HASH OK".
        assert_eq!(RU.crypto_hash, "HASH");
        assert_eq!(EN.crypto_hash, "HASH");
    }

    #[test]
    fn stage_five_is_shadow_copies_never_the_old_vss_wording_in_russian() {
        assert_eq!(RU.stage_short[4], "Теневые копии");
        assert_ne!(RU.stage_short[4], "VSS Shadow Storage");
        assert!(EN.stage_short[4].to_lowercase().contains("shadow"));
    }

    #[test]
    fn every_stage_array_has_all_fourteen_entries_in_both_languages() {
        assert_eq!(RU.stage_short.len(), 14);
        assert_eq!(RU.stage_description.len(), 14);
        assert_eq!(EN.stage_short.len(), 14);
        assert_eq!(EN.stage_description.len(), 14);
        for s in RU.stage_short.iter().chain(EN.stage_short.iter()) {
            assert!(!s.trim().is_empty());
        }
    }

    #[test]
    fn stability_status_codes_stay_language_neutral() {
        // These are diagnostic status codes, not translated text — the
        // dictionaries deliberately have no STABLE/ACCEPT/UNSTABLE fields
        // at all, so there is nothing here that could diverge by language.
        assert!(std::ptr::eq(t(Language::Ru), &RU));
        assert!(std::ptr::eq(t(Language::En), &EN));
    }

    #[test]
    fn load_falls_back_to_russian_when_nothing_is_stored() {
        let dir = std::env::temp_dir().join(format!("wsd-i18n-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load(&dir), Language::Ru);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trips_a_saved_language_preference() {
        let dir = std::env::temp_dir().join(format!("wsd-i18n-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        save(&dir, Language::En);
        assert_eq!(load(&dir), Language::En);
        save(&dir, Language::Ru);
        assert_eq!(load(&dir), Language::Ru);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupted_preference_file_falls_back_safely_and_never_panics() {
        let dir = std::env::temp_dir().join(format!("wsd-i18n-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(pref_path(&dir), b"\x00\xff not a language garbage 123").unwrap();
        assert_eq!(load(&dir), Language::Ru);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_to_an_unwritable_directory_never_panics() {
        // A path whose parent does not exist: write() fails, save() must
        // swallow it rather than propagate or panic.
        let dir = std::path::PathBuf::from("/definitely/not/a/real/path/at-all");
        save(&dir, Language::En);
    }

    // ---- v0.3.6 Visual Master alignment: driver-popup / hw-progress ----

    #[test]
    fn driver_popup_and_hardware_progress_strings_exist_in_both_languages() {
        for d in [&RU, &EN] {
            assert!(!d.driver_popup_running.is_empty());
            assert!(!d.driver_popup_retry.is_empty());
            assert!(!d.driver_popup_rerun.is_empty());
            assert!(!d.driver_popup_summary_fmt.is_empty());
            assert!(!d.driver_popup_note.is_empty());
            assert!(!d.driver_popup_device_fmt.is_empty());
            assert!(!d.driver_popup_provider_fmt.is_empty());
            assert!(!d.driver_popup_unattributed_note.is_empty());
            assert!(!d.driver_popup_collection_error_fmt.is_empty());
            assert!(!d.hw_progress_title.is_empty());
            assert!(!d.hw_progress_collecting.is_empty());
            assert!(!d.hw_progress_saving.is_empty());
            assert!(!d.hw_progress_please_wait.is_empty());
            assert!(!d.report_not_ready_error.is_empty());
            assert!(!d.driver_journal_summary_fmt.is_empty());
            assert!(!d.driver_journal_added_fmt.is_empty());
        }
        // Never accidentally identical between languages (a copy-paste bug).
        assert_ne!(RU.driver_popup_note, EN.driver_popup_note);
        assert_ne!(RU.hw_progress_title, EN.hw_progress_title);
    }

    #[test]
    fn approved_expc_diagnostics_wording_matches_exactly() {
        assert_eq!(RU.expc_title, "Диагностика ПК EXPC");
        assert_eq!(RU.expc_mode_standard, "Основная");
        assert_eq!(RU.expc_mode_deep, "Глубокие проверки...");
        assert_eq!(RU.expc_mode_full, "Полная");
        assert_eq!(EN.expc_title, "EXPC PC Diagnostics");
        assert_eq!(EN.expc_mode_standard, "Standard");
        assert_eq!(EN.expc_mode_deep, "Deep checks...");
        assert_eq!(EN.expc_mode_full, "Full");
    }

    #[test]
    fn approved_result_and_bottom_action_wording_matches_exactly() {
        assert_eq!(RU.result_open_report_button, "Отчёт");
        assert_eq!(RU.result_open_folder_button, "Папка");
        assert_eq!(RU.new_diagnostics_button, "Новая диагностика");
        assert_eq!(EN.result_open_report_button, "Report");
        assert_eq!(EN.result_open_folder_button, "Folder");
        assert_eq!(EN.new_diagnostics_button, "New Diagnostics");
    }

    #[test]
    fn stage_five_is_shadow_copies_in_english_never_vss_shadow_storage() {
        assert_eq!(EN.stage_short[4], "Shadow copies");
        assert_ne!(EN.stage_short[4], "VSS Shadow Storage");
    }

    // ---- Final remaster: complete, unmixed RU / EN dictionaries ----

    /// Every string value of a dictionary (via its Debug output), so a new
    /// field can never slip in untranslated.
    fn all_strings(d: &Dict) -> Vec<String> {
        let dbg = format!("{d:?}");
        let mut out = Vec::new();
        let mut chars = dbg.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '"' {
                let mut v = String::new();
                while let Some(n) = chars.next() {
                    match n {
                        '\\' => {
                            if let Some(e) = chars.next() {
                                v.push(e);
                            }
                        }
                        '"' => break,
                        _ => v.push(n),
                    }
                }
                out.push(v);
            }
        }
        out
    }

    fn has_cyrillic(s: &str) -> bool {
        s.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c))
    }

    #[test]
    fn english_dictionary_contains_no_russian_at_all() {
        let strings = all_strings(&EN);
        assert!(strings.len() > 150, "walked {} strings", strings.len());
        for v in strings {
            assert!(!v.trim().is_empty() || v.is_empty(), "blank EN value");
            assert!(
                !has_cyrillic(&v),
                "Russian text in the EN dictionary: {v:?}"
            );
        }
    }

    #[test]
    fn russian_dictionary_uses_only_approved_technical_latin_terms() {
        // Universal technical terms / proper names allowed inside Russian UI.
        const ALLOWED: &[&str] = &[
            "READ",
            "WRITE",
            "HASH",
            "SSD",
            "NVMe",
            "SFC",
            "DISM",
            "CHKDSK",
            "STABLE",
            "ACCEPT",
            "UNSTABLE",
            "MB",
            "ETA",
            "EXPC",
            "Windows",
            "WinStateDiag",
            "CPU",
            "GPU",
            "ZIP",
            "WHEA",
            "CPER",
            "BSOD",
            "Defender",
            "Microsoft",
            "BIOS",
            "PnP",
            "VSS",
            "Volsnap",
            "Kernel",
            "Power",
            "Memory",
            "Diagnostic",
            "Plug",
            "and",
            "Play",
            "Code",
            "Integrity",
            "INF",
            "verifyonly",
            "ScanHealth",
            "scan",
            "WARN",
            "INFO",
            "PhysicalDrive",
            "OK",
        ];
        for v in all_strings(&RU) {
            let mut word = String::new();
            for c in v.chars().chain(std::iter::once(' ')) {
                if c.is_ascii_alphabetic() || c == '_' {
                    word.push(c);
                } else {
                    if word.len() >= 2 && !ALLOWED.contains(&word.as_str()) {
                        // `{placeholders}` are template slots, not UI text.
                        let slot = format!("{{{word}");
                        assert!(
                            v.contains(&slot),
                            "English word {word:?} in Russian UI text {v:?}"
                        );
                    }
                    word.clear();
                }
            }
        }
    }

    #[test]
    fn both_dictionaries_fill_every_field() {
        // Same number of values (no field left out of one language) and
        // no empty user-visible value in either.
        let (ru, en) = (all_strings(&RU), all_strings(&EN));
        assert_eq!(ru.len(), en.len());
        for v in ru.iter().chain(en.iter()) {
            assert!(!v.is_empty(), "empty dictionary value");
        }
    }

    #[test]
    fn required_russian_wording_matches_exactly() {
        let d = &RU;
        for (got, want) in [
            (d.header_subtitle, "Диагностический центр состояния Windows"),
            (d.client_label, "Клиент"),
            (d.computer_label, "Компьютер"),
            (d.expc_title, "Диагностика ПК EXPC"),
            (d.expc_mode_standard, "Основная"),
            (d.expc_mode_deep, "Глубокие проверки..."),
            (d.expc_mode_full, "Полная"),
            (d.hardware_title, "Отчёт об оборудовании"),
            (d.hardware_view_button, "Смотреть"),
            (d.overall_title, "ОБЩИЙ ХОД ВЫПОЛНЕНИЯ"),
            (d.overall_elapsed, "Прошло"),
            (d.overall_eta, "Осталось (ETA)"),
            (d.overall_modules_title, "Модули диагностики"),
            (d.module_status_done, "Выполнено"),
            (d.module_status_waiting, "Ожидание"),
            (d.module_name_expc, "Диагностика ПК EXPC"),
            (d.module_name_hardware, "Отчёт об оборудовании"),
            (d.module_name_zip, "ZIP-отчёт"),
            (d.stages_title_prefix, "EXPC — ЭТАПЫ ДИАГНОСТИКИ"),
            (d.stage_short[0], "Сведения о системе"),
            (d.stage_short[1], "Накопители и хранилище"),
            (d.stage_short[2], "Устройства и драйверы"),
            (d.stage_short[3], "События системы"),
            (d.stage_short[4], "Теневые копии"),
            (d.driver_title, "ПРОВЕРКА ДРАЙВЕРОВ"),
            (d.driver_details_button, "Подробнее"),
            (d.driver_status_warning, "Внимание"),
            (d.driver_status_problem, "Проблема"),
            (d.driver_status_ok, "OK"),
            (d.result_title, "РЕЗУЛЬТАТ"),
            (d.result_ready, "Отчёт готов"),
            (d.result_open_report_button, "Отчёт"),
            (d.result_open_folder_button, "Папка"),
            (d.curop_title, "Текущая операция"),
            (d.curop_waiting_name, "Ожидание запуска"),
            (d.curop_done_name, "Диагностика завершена"),
            (d.ssd_title, "Отчёт диагностики SSD / NVMe дисков"),
            (d.ssd_subtitle, "Выберите накопитель для тестирования:"),
            (d.ssd_info_title, "Информация о выбранном диске"),
            (d.ssd_model_label, "Модель:"),
            (d.ssd_capacity_label, "Ёмкость:"),
            (d.ssd_interface_label, "Интерфейс:"),
            (d.ssd_serial_label, "Серийный №:"),
            (d.ssd_status_label, "Состояние:"),
            (d.ssd_state_ready, "Готов к тесту"),
            (d.ssd_start_button, "Запустить тест"),
            (d.ssd_rerun_button, "Запустить повторно"),
            (d.ssd_details_button, "Детали"),
            (d.ssd_profile_label, "Профиль"),
            (d.ssd_passes_label, "Проходы"),
            (d.ssd_duration_label, "Длительность"),
            (d.ssd_read_spread_label, "Разброс чтения"),
            (d.ssd_write_spread_label, "Разброс записи"),
            (d.ssd_stability_label, "Стабильность"),
            (d.ssd_empty_slot, "SSD не обнаружен"),
            (d.journal_title, "Журнал"),
            (d.journal_clear_button, "Очистить"),
            (d.journal_open_button, "Открыть"),
            (d.journal_viewer_title, "Журнал WinStateDiag"),
            (d.journal_viewer_save, "Сохранить"),
            (d.journal_viewer_copy, "Копировать"),
            (d.journal_viewer_close, "Закрыть"),
            (d.journal_viewer_saved, "Журнал сохранён"),
            (d.journal_viewer_save_failed, "Не удалось сохранить журнал"),
            (
                d.deep_check_findings[1][1],
                "DISM: хранилище компонентов Windows требует восстановления.",
            ),
            (d.new_diagnostics_button, "Новая диагностика"),
            (d.status_diag_done, "Диагностика завершена"),
            (d.crypto_hash, "HASH"),
            (d.crypto_rehash_button, "Проверка"),
        ] {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn required_english_wording_matches_exactly() {
        let d = &EN;
        for (got, want) in [
            (d.header_subtitle, "Windows System Diagnostics Center"),
            (d.client_label, "Client"),
            (d.computer_label, "Computer"),
            (d.expc_title, "EXPC PC Diagnostics"),
            (d.expc_mode_standard, "Standard"),
            (d.expc_mode_deep, "Deep checks..."),
            (d.expc_mode_full, "Full"),
            (d.hardware_title, "Hardware Report"),
            (d.hardware_view_button, "View"),
            (d.overall_title, "OVERALL PROGRESS"),
            (d.overall_elapsed, "Elapsed"),
            (d.overall_eta, "Remaining (ETA)"),
            (d.overall_modules_title, "Diagnostic Modules"),
            (d.module_status_done, "Completed"),
            (d.module_status_waiting, "Waiting"),
            (d.module_name_expc, "EXPC PC Diagnostics"),
            (d.module_name_hardware, "Hardware Report"),
            (d.module_name_zip, "ZIP Report"),
            (d.stages_title_prefix, "EXPC — DIAGNOSTIC STEPS"),
            (d.stage_short[0], "System information"),
            (d.stage_short[1], "Storage and drives"),
            (d.stage_short[2], "Devices and drivers"),
            (d.stage_short[3], "System events"),
            (d.stage_short[4], "Shadow copies"),
            (d.driver_title, "DRIVER CHECK"),
            (d.driver_details_button, "Details"),
            (d.driver_status_warning, "Warning"),
            (d.driver_status_problem, "Problem"),
            (d.driver_status_ok, "OK"),
            (d.result_title, "RESULT"),
            (d.result_ready, "Report ready"),
            (d.result_open_report_button, "Report"),
            (d.result_open_folder_button, "Folder"),
            (d.curop_title, "Current Operation"),
            (d.curop_waiting_name, "Waiting to start"),
            (d.curop_done_name, "Diagnostics completed"),
            (d.ssd_title, "SSD / NVMe Diagnostic Report"),
            (d.ssd_subtitle, "Select a drive to test:"),
            (d.ssd_info_title, "Selected Drive Information"),
            (d.ssd_model_label, "Model:"),
            (d.ssd_capacity_label, "Capacity:"),
            (d.ssd_interface_label, "Interface:"),
            (d.ssd_serial_label, "Serial No.:"),
            (d.ssd_status_label, "Status:"),
            (d.ssd_state_ready, "Ready for test"),
            (d.ssd_start_button, "Run Test"),
            (d.ssd_rerun_button, "Run Test Again"),
            (d.ssd_details_button, "Details"),
            (d.ssd_profile_label, "Profile"),
            (d.ssd_passes_label, "Passes"),
            (d.ssd_duration_label, "Duration"),
            (d.ssd_read_spread_label, "Read spread"),
            (d.ssd_write_spread_label, "Write spread"),
            (d.ssd_stability_label, "Stability"),
            (d.ssd_empty_slot, "No SSD detected"),
            (d.journal_title, "Log"),
            (d.journal_clear_button, "Clear"),
            (d.journal_open_button, "Open"),
            (d.journal_viewer_title, "WinStateDiag Log"),
            (d.journal_viewer_save, "Save"),
            (d.journal_viewer_copy, "Copy"),
            (d.journal_viewer_close, "Close"),
            (d.journal_viewer_saved, "Log saved"),
            (d.journal_viewer_save_failed, "Failed to save log"),
            (
                d.deep_check_findings[1][1],
                "DISM: the Windows component store is repairable.",
            ),
            (d.new_diagnostics_button, "New Diagnostics"),
            (d.status_diag_done, "Diagnostics completed"),
            (d.crypto_hash, "HASH"),
            (d.crypto_rehash_button, "ReHash"),
        ] {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn driver_audit_popup_is_localized_in_both_languages() {
        let fields = |d: &Dict| {
            [
                d.driver_details_title,
                d.driver_popup_running,
                d.driver_popup_retry,
                d.driver_popup_rerun,
                d.driver_popup_summary_fmt,
                d.driver_popup_note,
                d.driver_popup_device_fmt,
                d.driver_popup_provider_fmt,
                d.driver_popup_event_fmt,
                d.driver_popup_last_seen_fmt,
                d.driver_popup_unattributed_note,
                d.driver_popup_collection_error_fmt,
                d.driver_na,
                d.driver_status_ok,
                d.driver_status_warning,
                d.driver_status_problem,
            ]
        };
        for v in fields(&EN) {
            assert!(!has_cyrillic(v), "Russian in the EN driver popup: {v:?}");
        }
        for (ru, en) in fields(&RU).iter().zip(fields(&EN)) {
            if *ru != "OK" {
                assert_ne!(*ru, en, "untranslated popup text {ru:?}");
            }
        }
        // Every placeholder the popup code fills exists in both languages.
        for d in [&RU, &EN] {
            for slot in [
                "{status}",
                "{problems}",
                "{warnings}",
                "{ok}",
                "{devices}",
                "{days}",
                "{generated}",
            ] {
                assert!(d.driver_popup_summary_fmt.contains(slot), "{slot}");
            }
            for slot in ["{provider}", "{date}", "{inf}", "{service}"] {
                assert!(d.driver_popup_provider_fmt.contains(slot), "{slot}");
            }
        }
    }
}
