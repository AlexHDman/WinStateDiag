//! UI-only translation of WinDiag captions. Raw evidence and device names remain unchanged.
use std::borrow::Cow;
const PAIRS: &[(&str, &str)] = &[
    (
        "Только выбранный ProductCode и подписанный локальный MSI. EXE/Store, регистрационная хирургия и DriverStore не поддерживаются. Diagcab не включён: совместимость не доказана. События анализа относятся только к точному ProductCode.",
        "Only the selected ProductCode and a signed local MSI are supported. EXE/Store, registry surgery and DriverStore operations are unsupported. Diagcab is not included because compatibility is unverified. Analyzed events match the exact ProductCode only.",
    ),
    (
        "Используемые файлы, ссылки и изменённые объекты пропускаются. Браузеры, проекты, документы, корзина, Windows.old и восстановление автоматически не очищаются.",
        "In-use files, links and changed objects are skipped. Browsers, projects, documents, the Recycle Bin, Windows.old and recovery data are not cleaned automatically.",
    ),
    (
        "Фактическая сводка без обращения к ИИ. Проверь замечания и ограничения первичного отчёта. Ремонт автоматически не запускался.",
        "Evidence-only summary without an AI request. Review the findings and original report limitations. No automatic repair was performed.",
    ),
    (
        "При аппаратных ошибках сначала сохрани данные. /r, принудительное отключение и автоматическая перезагрузка не выполняются.",
        "Back up important data first if hardware errors are suspected. No /r, forced dismount or automatic reboot is performed.",
    ),
    (
        "Ниже — точная копия input запроса. Проверь свободный текст: автоматическое маскирование не гарантирует анонимность.",
        "Below is the exact request input. Review free text: automatic masking does not guarantee anonymity.",
    ),
    (
        "Ключ хранится только в Windows Credential Manager текущего пользователя. В отчёт и настройки он не записывается.",
        "The key is stored only in the current user Windows Credential Manager, never in reports or settings.",
    ),
    (
        "Отмена останавливает ожидание. Уже отправленный запрос может быть оплачен; автоматического повтора нет.",
        "Cancel stops waiting. A request already sent may still be billed; there is no automatic retry.",
    ),
    (
        "Оснований для обслуживания кэша в анализе не найдено. Это не проверка установки обновлений.",
        "The analysis found no reason to maintain the cache. This does not verify update installation.",
    ),
    (
        "OpenAI API оплачивается отдельно. Доступность указанной модели зависит от проекта OpenAI.",
        "OpenAI API usage is billed separately. Model availability depends on your OpenAI project.",
    ),
    (
        "Нажатие «Отправить в OpenAI» разрешает платный запрос с показанными текстом и моделью.",
        "Clicking Send to OpenAI authorizes a paid request using the displayed text and model.",
    ),
    (
        "Выбери сохранённый TXT или завершённую сессию для подготовки отправляемой копии.",
        "Choose a saved TXT or a completed session to prepare the outgoing copy.",
    ),
    (
        "Выполни диагностическую проверку SFC/DISM, чтобы получить обоснованный план.",
        "Run the SFC/DISM diagnostic checks to obtain an evidence-based plan.",
    ),
    (
        "Источник — только сохранённые материалы. Новая диагностика не запускается.",
        "Saved evidence only. No new diagnostic scan is started.",
    ),
    (
        "Сначала выполни анализ системы. Удаление для этих категорий недоступно.",
        "Analyze the system first. Deletion is unavailable for these categories.",
    ),
    (
        "Сначала анализ и план. Изменения — только после твоего подтверждения.",
        "Analyze and review the plan first. Changes require your explicit confirmation.",
    ),
    (
        "Оценка объёма появится после анализа. Анализ ничего не удаляет.",
        "A size estimate will appear after analysis. Analysis deletes nothing.",
    ),
    (
        "Ответ получен. Заключение можно сохранить без нового запроса.",
        "Response received. Save the conclusion without another request.",
    ),
    (
        "Получен неполный ответ. Проверь ограничения и исходный текст.",
        "Incomplete response received. Review limitations and original output.",
    ),
    (
        "Ключ не настроен. Подготовка и просмотр доступны без ключа.",
        "No key configured. Preparation and preview remain available.",
    ),
    (
        "Проверка Windows Update неполная — часть данных недоступна",
        "Windows Update check is incomplete: some data is unavailable",
    ),
    (
        "Паспорт, SPD и параметры источника · без статистики сеанса",
        "Identity, SPD and source parameters · no session statistics",
    ),
    (
        "Причины неисправностей не выводятся из отсутствия данных.",
        "Missing data does not establish a fault cause.",
    ),
    (
        "Объект проверен; последствия понятны; разрешаю этот план",
        "The target is verified; I understand the consequences and authorize this plan",
    ),
    (
        "Политики и ACL не сбрасываются. Старый кэш сохраняется.",
        "Policies and ACLs are not reset. The previous cache is preserved.",
    ),
    (
        "Текст подготовлен. Проверь отправляемую копию и модель.",
        "Text is ready. Review the outgoing copy and model.",
    ),
    (
        "Заключение сохранено рядом с исходным отчётом",
        "Conclusion saved next to the source report",
    ),
    (
        "Штатное обслуживание Windows, без ResetBase.",
        "Standard Windows maintenance, without ResetBase.",
    ),
    (
        "Запрос отправляется в OpenAI. Ожидаю ответ…",
        "Sending request to OpenAI. Waiting for the response…",
    ),
    (
        "Каналы без данных, неопознанные и источники",
        "Unavailable/unknown channels and sources",
    ),
    (
        "Нет доступных показаний выбранного раздела",
        "No available readings for this section",
    ),
    (
        "Доступно проверенных файлов эскизов: {}",
        "Verified thumbnail files available: {}",
    ),
    (
        "Intel Chipset и технические ограничения",
        "Intel Chipset and technical limitations",
    ),
    (
        "Анализ Windows Update ещё не выполнен.",
        "Windows Update analysis has not run yet.",
    ),
    (
        "Проверь план и источник восстановления",
        "Review the plan and recovery source",
    ),
    (
        "Нет сопоставимых измерений для графика",
        "No comparable measurements for this chart",
    ),
    (
        "Сопоставимая история не представлена.",
        "No comparable history is available.",
    ),
    (
        "Список томов появится после анализа.",
        "The volume list will appear after analysis.",
    ),
    (
        "В выбранных данных не подтверждены.",
        "Not confirmed by the selected evidence.",
    ),
    (
        "Ключ сохранён в Credential Manager",
        "Key saved in Credential Manager",
    ),
    (
        "Анализировать систему и программы",
        "Analyze system and applications",
    ),
    (
        "Подготовка и маскирование текста…",
        "Preparing and masking text…",
    ),
    (
        "Ключ удалён из Credential Manager",
        "Key removed from Credential Manager",
    ),
    (
        "Подтверждённые выполненные работы",
        "Confirmed completed work",
    ),
    (
        "Другие категории · только анализ",
        "Other categories · analysis only",
    ),
    (
        "Телеметрия · последние показания",
        "Telemetry · latest readings",
    ),
    (
        "Нет данных в выбранном интервале",
        "No data in the selected interval",
    ),
    (
        "План обслуживания кэша загрузок",
        "Download cache maintenance plan",
    ),
    (
        "Категории, объёмы и ограничения",
        "Categories, sizes and limitations",
    ),
    (
        "Выбрать Chipset Device Software",
        "Select Chipset Device Software",
    ),
    (
        "Диалог выбора отчёта недоступен",
        "Report selection dialog is unavailable",
    ),
    ("Сохранён для этого пользователя", "Saved for this user"),
    (
        "Обнаружение доступных датчиков…",
        "Discovering available sensors…",
    ),
    (
        "План очистки выбранных эскизов",
        "Selected thumbnail cleanup plan",
    ),
    ("СВОДКА СОХРАНЁННЫХ РЕЗУЛЬТАТОВ", "SAVED DIAGNOSTIC SUMMARY"),
    ("Восстановление Windows Update", "Windows Update recovery"),
    ("Файловая система и накопители", "File systems and drives"),
    (
        "Установка и удаление программ",
        "Install and uninstall applications",
    ),
    ("Событий ошибок обновления: {}", "Update error events: {}"),
    ("Последний CHKDSK: подробности", "Last CHKDSK: details"),
    (
        "План обслуживания компонентов",
        "Component maintenance plan",
    ),
    ("Установка из подписанного MSI", "Install from a signed MSI"),
    (
        "Проверить пакет без установки",
        "Verify package without installation",
    ),
    ("PNG сохранён на рабочем столе", "PNG saved to Desktop"),
    (
        "Службы и подробности анализа",
        "Services and analysis details",
    ),
    ("Сохранённых операций ещё нет", "No saved operations yet"),
    (
        "PNG сохранён рядом с отчётом",
        "PNG saved next to the report",
    ),
    ("Компоненты Windows / WinSxS", "Windows components / WinSxS"),
    (
        "План установки этого пакета",
        "Installation plan for this package",
    ),
    ("Выполнение выбранного плана", "Executing selected plan"),
    ("Текущая завершённая сессия", "Current completed session"),
    ("Проверка ещё не выполнена", "The check has not run yet"),
    ("Проверить без исправлений", "Check without repairs"),
    ("Сравнить с предыдущим ZIP", "Compare with a previous ZIP"),
    ("Сохранённая операция · {}", "Saved operation · {}"),
    ("Обнаружение оборудования…", "Discovering hardware…"),
    ("Исправление не требуется", "No repair required"),
    ("Проверить Windows Update", "Check Windows Update"),
    ("Установленная программа:", "Installed application:"),
    ("Выполнить выбранный план", "Execute selected plan"),
    ("ПРОВЕРКА С ОГРАНИЧЕНИЯМИ", "LIMITED COVERAGE"),
    ("Технические подробности", "Technical details"),
    ("Ключ OpenAI не настроен", "OpenAI key is not configured"),
    ("Изображение скопировано", "Image copied"),
    ("Восстановление Windows", "Windows recovery"),
    ("Очистка и обслуживание", "Cleanup and maintenance"),
    ("Выбрать эскизы Windows", "Select Windows thumbnails"),
    ("Подробности выполнения", "Execution details"),
    ("Мониторинг выполняется", "Monitoring in progress"),
    ("ДИАГНОСТИКА КОМПЬЮТЕРА", "COMPUTER DIAGNOSTICS"),
    ("Заключение для клиента", "Client conclusion"),
    ("План исправления тома", "Volume repair plan"),
    ("Пропущенные материалы", "Omitted materials"),
    ("Мониторинг остановлен", "Monitoring stopped"),
    ("Замечания по важности", "Findings by importance"),
    ("Создаю локальный PNG…", "Creating local PNG…"),
    ("Создание PNG прервано", "PNG creation interrupted"),
    ("Нарушений не найдено", "No violations found"),
    ("Сбор и анализ данных", "Collecting and analyzing data"),
    ("Операция не запущена", "No operation started"),
    ("История и результаты", "History and results"),
    ("Получить права (UAC)", "Request access (UAC)"),
    ("Недостаточно данных", "Insufficient data"),
    ("План восстановления", "Recovery plan"),
    ("Отправляемый текст", "Outgoing text"),
    ("Отправить в OpenAI", "Send to OpenAI"),
    ("Завершение чтения…", "Stopping the reader…"),
    ("Паспорт компьютера", "Computer passport"),
    ("Выбранный том: {}", "Selected volume: {}"),
    ("Прочитать историю", "Read history"),
    ("Отменить ожидание", "Cancel waiting"),
    ("Расход не получен", "Usage not received"),
    ("Установить PawnIO", "Install PawnIO"),
    ("Требует внимания", "Needs attention"),
    ("AI-разбор отчёта", "AI report"),
    ("Проверить доступ", "Check access"),
    ("ТРЕБУЕТ ВНИМАНИЯ", "NEEDS ATTENTION"),
    ("Ошибка проверки", "Check failed"),
    ("План DISM → SFC", "DISM → SFC plan"),
    ("Условия и риски", "Conditions and risks"),
    ("Отменить анализ", "Cancel analysis"),
    ("Не выполнялось", "Not run"),
    ("Эскизы Windows", "Windows thumbnails"),
    ("Путь к пакету:", "Package path:"),
    ("Ход выполнения", "Execution progress"),
    ("{} · завершено", "{} · completed"),
    ("Сохранить ключ", "Save key"),
    ("Что изменилось", "What changed"),
    ("Анализ WinSxS", "Analyze WinSxS"),
    ("Анализ ошибок", "Analyze errors"),
    ("План удаления", "Uninstall plan"),
    ("График сеанса", "Session chart"),
    ("{} · {} байт", "{} · {} bytes"),
    ("Прошло: {} с", "Elapsed: {} s"),
    ("Выбрать TXT…", "Choose TXT…"),
    ("Удалить ключ", "Delete key"),
    ("подтверждён", "confirmed"),
    ("Новый сеанс", "New session"),
    ("Выбери том", "Select a volume"),
    ("нет данных", "no data"),
    ("Нет данных", "No data"),
    ("Объект: {}", "Target: {}"),
    ("Видеокарта", "GPU"),
    ("Накопители", "Storage"),
    ("Охлаждение", "Cooling"),
    ("План DISM", "DISM plan"),
    ("не выбран", "not selected"),
    ("Результат", "Result"),
    ("Процессор", "CPU"),
    ("Последнее", "Last"),
    ("План SFC", "SFC plan"),
    ("Службы:", "Services:"),
    ("Модель:", "Model:"),
    ("▶ Старт", "▶ Start"),
    ("Экспорт", "Export"),
    ("Ремонт", "Repair"),
    ("РЕМОНТ", "REPAIR"),
    ("Память", "Memory"),
    ("■ Стоп", "■ Stop"),
    ("Датчик", "Sensor"),
    ("Сейчас", "Now"),
    ("Ключ:", "Key:"),
    ("Обзор", "Overview"),
    ("Плата", "Motherboard"),
    ("Старт", "Start"),
    ("Макс.", "Max."),
    ("Стоп", "Stop"),
    ("Мин.", "Min."),
    ("ДИАГНОСТИКА КОМПЬЮТЕРА", "COMPUTER DIAGNOSTICS"),
    ("Паспорт компьютера", "Computer passport"),
    ("Плата: {}", "Motherboard: {}"),
    ("BIOS: {} · ОЗУ: {}", "BIOS: {} · RAM: {}"),
    ("ТРЕБУЕТ ВНИМАНИЯ", "ATTENTION REQUIRED"),
    ("ПРОВЕРКА С ОГРАНИЧЕНИЯМИ", "CHECKED WITH LIMITATIONS"),
    ("СВОДКА СОХРАНЁННЫХ РЕЗУЛЬТАТОВ", "SAVED RESULTS SUMMARY"),
    (
        "Причины неисправностей не выводятся из отсутствия данных.",
        "Missing data does not establish a cause of failure.",
    ),
    ("Замечания по важности", "Findings by priority"),
    (
        "Подтверждённые замечания не извлечены. Проверь ограничения и первичные материалы.",
        "No confirmed findings extracted. Review limitations and primary evidence.",
    ),
    ("Что изменилось", "What changed"),
    (
        "Сопоставимая история не представлена.",
        "No comparable history provided.",
    ),
    (
        "Подтверждённые выполненные работы",
        "Confirmed completed work",
    ),
    (
        "В выбранных данных не подтверждены.",
        "Not confirmed in the selected evidence.",
    ),
    ("Заключение для клиента", "Client conclusion"),
    (
        "Фактическая сводка без обращения к ИИ. Проверь замечания и ограничения первичного отчёта. Ремонт автоматически не запускался.",
        "Factual summary without AI. Review the original findings and limitations. No repairs were started automatically.",
    ),
    (
        "Ограничений: {}. Полные доказательства сохранены в исходном отчёте.",
        "Limitations: {}. Full evidence remains in the original report.",
    ),
    (
        "Подробности в журнале · доступен повторный экспорт",
        "See journal for details · export can be retried",
    ),
    (
        "Некоторые проверки не удались · подробности в этапах",
        "Some checks failed · see stage details",
    ),
    (
        "Обнаружены замечания · см. результаты проверок",
        "Findings detected · see check results",
    ),
    (
        "Режим: Основная · глубокие проверки не выбирались",
        "Mode: Standard · deep checks were not selected",
    ),
    (
        "Часть данных недоступна или не поддерживается · см. этапы",
        "Some data is unavailable or unsupported · see stages",
    ),
    (
        "Выбранные проверки завершены · результаты в таблице этапов",
        "Selected checks completed · see stage results",
    ),
    (
        "Текущий этап и результаты показаны ниже",
        "Current stage and results are shown below",
    ),
    ("Создаю локальный PNG…", "Creating local PNG…"),
    (
        "PNG сохранён рядом с отчётом",
        "PNG saved beside the report",
    ),
    ("Создание PNG прервано", "PNG creation interrupted"),
    (
        "Предыдущий отчёт проверен. Модель повторно не вызывалась.",
        "Previous report checked. No additional model request.",
    ),
    (
        "Нет текущего заключения для сравнения",
        "No current analysis to compare",
    ),
    (
        "Ответ предыдущего выбора отброшен: источник изменился",
        "Previous selection discarded: source changed",
    ),
    ("● Мониторинг выполняется", "● Monitoring"),
    ("Ожидание запуска", "Waiting to start"),
    ("{} измерений", "{} samples"),
    ("{} · завершено", "{} · completed"),
    ("Анализ завершён", "Analysis completed"),
    (
        "Выполнено частично; проверь пропуски",
        "Partially completed; review omissions",
    ),
    (
        "Операция завершена; исправность не подтверждена",
        "Operation completed; health not verified",
    ),
    ("История загружена", "History loaded"),
    ("Сравнение отчётов", "Report comparison"),
    ("Удаление продукта подтверждено", "Product removal verified"),
    ("Требуется ручная перезагрузка", "Manual restart required"),
    ("Ошибка выполнения", "Execution error"),
    (
        "Анализ выбранной программы завершён; отсутствие событий не доказывает исправность",
        "Selected program analyzed; absence of events does not prove health",
    ),
    (
        "Пакет проверен; установка не запускалась",
        "Package checked; installation was not started",
    ),
    (
        "Очистка выбранных объектов завершена",
        "Selected objects cleaned",
    ),
    (
        "Проверка завершена; см. результат",
        "Check completed; see result",
    ),
    ("Результат не подтверждён", "Result not verified"),
    ("Неожиданное завершение работы", "Unexpected shutdown"),
    (
        "Исторический номер диска не идентифицирует нынешний накопитель. Причина не установлена.",
        "A historical disk number does not identify the current drive. Cause not established.",
    ),
    (
        "Зафиксирован инцидент выключения. Причина не установлена; события 41/6008 не доказывают неисправность питания.",
        "A shutdown incident was recorded. Cause not established; events 41/6008 do not prove a power supply fault.",
    ),
    (
        "Проверить повторяемость, связанные BugCheck/WHEA и журналы за тот же интервал.",
        "Review recurrence, related BugCheck/WHEA and logs for the same interval.",
    ),
    (
        "Уточнить подключённое в тот момент устройство и сохранить важные данные перед операциями записи.",
        "Identify the device connected at the time and back up important data before write operations.",
    ),
    (
        "Сбой обращения к диску · событие 154 · {} записей",
        "Disk access failure · event 154 · {} records",
    ),
    ("История графика", "Chart history"),
    ("Последние", "Latest"),
    (
        "НЕПОЛНЫЙ ОТВЕТ — это не окончательное заключение",
        "INCOMPLETE RESPONSE — not a final conclusion",
    ),
    ("Неполный текст ответа", "Incomplete response text"),
    (
        "Предложенные действия автоматически не выполняются.",
        "Suggested actions are never executed automatically.",
    ),
    ("Сохранить заключение TXT", "Save conclusion TXT"),
    (
        "План не подтверждён или недопустим",
        "Plan is not confirmed or invalid",
    ),
    (
        "Другая операция ещё выполняется",
        "Another operation is still running",
    ),
    (
        "План устарел: повтори анализ выбранного объекта",
        "Plan expired: analyze the selected target again",
    ),
    ("История ремонта", "Repair history"),
    ("Проверка MSI-пакета", "MSI package check"),
    (
        "Анализ ошибок выбранной программы",
        "Selected application error analysis",
    ),
    (
        "Установка выбранного MSI-пакета",
        "Install selected MSI package",
    ),
    (
        "Сравнение диагностических отчётов",
        "Diagnostic report comparison",
    ),
    (
        "Очистка выбранных эскизов Windows",
        "Clean selected Windows thumbnails",
    ),
    (
        "Обслуживание кэша Windows Update",
        "Windows Update cache maintenance",
    ),
    ("Проверка тома", "Volume check"),
    ("Исправление тома", "Volume repair"),
    ("Восстановление программы", "Application repair"),
    ("Удаление программы", "Application removal"),
    ("Анализ хранилища компонентов", "Component store analysis"),
    ("Обслуживание компонентов", "Component maintenance"),
    (
        "Анализ и проверка не запрашивают исправление.",
        "Analysis and checking do not request repairs.",
    ),
    (
        "Объект не указан в старой записи",
        "Target not specified in the legacy record",
    ),
    ("Анализ системы", "System analysis"),
    ("Обслуживание Windows Update", "Windows Update maintenance"),
    ("Установка программы", "Application installation"),
    ("Очистка эскизов", "Thumbnail cleanup"),
    ("Просмотр истории", "View history"),
    (
        "Будет установлен выбранный подписанный MSI-пакет. Установщик может выполнять собственные изменения системы. Подпись не гарантирует безопасность. Автоматическая перезагрузка запрещена.",
        "The selected signed MSI will be installed. Its installer can change the system. A signature does not guarantee safety. Automatic restart is prohibited.",
    ),
    (
        "Будут удалены только выбранные базы эскизов. Windows создаст их повторно. Изменённые или используемые файлы и ссылки пропускаются; удаление необратимо.",
        "Only selected thumbnail databases will be deleted. Windows recreates them. Changed or in-use files and links are skipped; deletion is irreversible.",
    ),
    (
        "Будет сохранён журнал ошибок и переименован только кэш загрузок Windows Update. Службы будут возвращены к исходному состоянию. Старые данные сохранятся. Политики и разрешения не меняются.",
        "Error logs will be saved and only the Windows Update download cache renamed. Services return to their initial state. Old data is preserved. Policies and permissions are unchanged.",
    ),
    (
        "CHKDSK /spotfix изменяет файловую систему. Занятый том не отключается принудительно. Автоматического согласия на перезагрузку нет. Сохрани резервную копию; аппаратный отказ накопителя эта операция не устраняет.",
        "CHKDSK /spotfix changes the file system. A busy volume is not forcibly dismounted. Restart is not approved automatically. Back up your data; this operation does not fix drive hardware failure.",
    ),
    (
        "Штатное восстановление выбранного MSI-продукта может запросить исходный установщик. Автоматическая перезагрузка запрещена.",
        "Standard repair of the selected MSI product may require the original installer. Automatic restart is prohibited.",
    ),
    (
        "Будет штатно удалён только выбранный MSI-продукт. Его настройки и данные могут быть утрачены. Удаление драйверов и DriverStore не выполняется.",
        "Only the selected MSI product will be uninstalled. Its settings and data may be lost. Drivers and DriverStore are not removed.",
    ),
    (
        "DISM StartComponentCleanup удаляет заменённые компоненты. ResetBase не используется. Возможность отката отдельных обновлений может сократиться.",
        "DISM StartComponentCleanup removes superseded components. ResetBase is not used. Rollback of individual updates may be limited.",
    ),
    (
        "Анализ и проверка не запрашивают исправление.",
        "Analysis and checking do not request repairs.",
    ),
    ("Анализ", "Analysis"),
    ("Датчики платы и вентиляторов", "Board sensors and fans"),
    ("Температура модулей памяти", "Memory module temperature"),
    (
        "Дополнительный опрос накопителей LHM",
        "Additional LHM storage sampling",
    ),
    ("Загрузка CPU (занятость)", "CPU load (busy)"),
    (
        "CPU Utility (работа относительно номинала)",
        "CPU Utility (relative to nominal)",
    ),
    (
        "Частота CPU (средняя, расчётная)",
        "CPU clock (average, calculated)",
    ),
    ("Мощность CPU (пакет)", "CPU package power"),
    ("Мощность ядер CPU", "CPU cores power"),
    ("Мощность встроенной графики", "Integrated graphics power"),
    ("Температура CPU", "CPU temperature"),
    ("Термотроттлинг CPU", "CPU thermal throttling"),
    ("Лимиты мощности CPU", "CPU power limits"),
    ("Занятая память", "Used memory"),
    ("Доступная память", "Available memory"),
    ("Загрузка памяти", "Memory load"),
    ("Тип устройства", "Device type"),
    ("Компьютер", "Computer"),
    ("Системная плата", "Motherboard"),
    ("Батарея", "Battery"),
    ("Сведения о батарее", "Battery information"),
    ("Видеоадаптер", "Display adapter"),
    ("Температура GPU", "GPU temperature"),
    ("Мощность GPU", "GPU power"),
    ("Лимит мощности GPU", "GPU power limit"),
    ("Загрузка GPU", "GPU load"),
    ("Занятость видеопамяти", "Video memory load"),
    ("Занятая видеопамять", "Used video memory"),
    ("Частота GPU", "GPU clock"),
    ("Частота видеопамяти", "Video memory clock"),
    ("Вентилятор GPU (скважность)", "GPU fan duty"),
    ("Температура hotspot GPU", "GPU hotspot temperature"),
    ("Напряжение ядра GPU", "GPU core voltage"),
    ("Напряжение GPU", "GPU voltage"),
    ("Температура памяти GPU", "GPU memory temperature"),
    ("Горячая точка GPU", "GPU hotspot"),
    ("Обороты вентилятора GPU", "GPU fan speed"),
    ("Температура CPU Package", "CPU package temperature"),
    ("Средняя температура ядер", "Average core temperature"),
    ("Максимальная температура ядер", "Maximum core temperature"),
    ("Занято памяти", "Memory used"),
    ("Доступно памяти", "Memory available"),
    ("Общая память графики", "Total shared graphics memory"),
    ("Занято общей памяти графики", "Used shared graphics memory"),
    ("Вентилятор CPU", "CPU fan"),
    ("Системный вентилятор", "System fan"),
    ("Частота встроенной графики", "Integrated graphics clock"),
    ("Ошибка источника", "Source error"),
    ("Система", "System"),
    ("Оборудование", "Hardware"),
    ("Выполнение", "Execution"),
    ("Полнота", "Coverage"),
    ("Восстановление", "Recovery"),
    ("без замечаний", "no findings"),
    ("неполные данные", "incomplete data"),
    ("нет достоверных данных", "no reliable data"),
    ("критическое замечание", "critical finding"),
    ("завершено", "completed"),
    ("ошибка", "error"),
    ("требует внимания", "attention required"),
    ("Что изменилось:", "What changed:"),
    (
        "Изменений по сопоставимым показателям нет",
        "No changes in comparable indicators",
    ),
    ("Источник", "Source"),
    ("Устройство", "Device"),
    ("Исходный датчик", "Raw sensor"),
    ("Исходная единица", "Raw unit"),
    ("Причина", "Reason"),
    ("не указан", "not specified"),
    ("напряжение", "voltage"),
    ("температура", "temperature"),
    ("частота", "clock"),
    ("показание", "reading"),
    ("Ошибка: {}", "Error: {}"),
    ("{} (дата неизвестна)", "{} (date unknown)"),
    (
        "{} · назначение не подтверждено",
        "{} · purpose unconfirmed",
    ),
    (
        "{} · единица не подтверждена источником",
        "{} · unit unconfirmed by source",
    ),
    (
        "Недостаточно данных для сравнения. Подробности сохранены в журнале.",
        "Insufficient data for comparison. Details are in the journal.",
    ),
    (
        "Часть данных отсутствует — сравнение неполное.",
        "Some data is missing; comparison is incomplete.",
    ),
];
pub fn literal(ru: bool, s: &'static str) -> &'static str {
    if ru {
        s
    } else {
        PAIRS
            .iter()
            .find(|(a, _)| *a == s)
            .map(|(_, b)| *b)
            .unwrap_or(s)
    }
}
pub fn text<'a>(ru: bool, s: &'a str) -> Cow<'a, str> {
    if ru {
        return Cow::Borrowed(s);
    }
    if let Some((_, v)) = PAIRS.iter().find(|(k, _)| *k == s) {
        return Cow::Borrowed(v);
    }
    for (k, v) in PAIRS {
        if !k.contains("{}") {
            continue;
        }
        let parts: Vec<_> = k.split("{}").collect();
        let target: Vec<_> = v.split("{}").collect();
        if parts.len() != target.len() {
            continue;
        }
        let Some(mut rest) = s.strip_prefix(parts[0]) else {
            continue;
        };
        let mut args = Vec::new();
        let mut matched = true;
        for (i, delimiter) in parts.iter().enumerate().skip(1) {
            if i == parts.len() - 1 {
                if let Some(arg) = rest.strip_suffix(delimiter) {
                    args.push(arg);
                    rest = "";
                } else {
                    matched = false;
                    break;
                }
            } else if !delimiter.is_empty() {
                if let Some((arg, tail)) = rest.split_once(delimiter) {
                    args.push(arg);
                    rest = tail;
                } else {
                    matched = false;
                    break;
                }
            } else {
                matched = false;
                break;
            }
        }
        if matched && rest.is_empty() {
            let mut out = target[0].to_owned();
            for (arg, suffix) in args.into_iter().zip(target.iter().skip(1)) {
                out.push_str(arg);
                out.push_str(suffix);
            }
            return Cow::Owned(out);
        }
    }
    Cow::Borrowed(s)
}

pub fn structured(ru: bool, s: &str) -> String {
    let full = text(ru, s);
    if ru || full != s {
        return full.into_owned();
    }
    for separator in ["\n", " · ", ": ", " → ", " №"] {
        if s.contains(separator) {
            return s
                .split(separator)
                .map(|part| structured(ru, part))
                .collect::<Vec<_>>()
                .join(separator);
        }
    }
    s.to_owned()
}
#[cfg(test)]
mod tests {
    #[test]
    fn translates_complete_templates_preserving_device_output_and_language_switch() {
        assert_eq!(
            super::text(false, "BIOS: 1.R0 · ОЗУ: 32 GB"),
            "BIOS: 1.R0 · RAM: 32 GB"
        );
        assert_eq!(
            super::text(true, "BIOS: 1.R0 · ОЗУ: 32 GB"),
            "BIOS: 1.R0 · ОЗУ: 32 GB"
        );
        assert_eq!(
            super::text(false, "original Windows failure 0x80070005"),
            "original Windows failure 0x80070005"
        );
    }
}

#[test]
fn v111_repair_plan_labels_and_risks_are_translated_without_execution() {
    use crate::repair_center::Operation as O;
    let operations = [
        O::Analyze,
        O::History,
        O::UpdateCache,
        O::CheckVolume("C:".into()),
        O::RepairVolume("C:".into()),
        O::MsiRepair("fixture".into()),
        O::MsiRemove("fixture".into()),
        O::AnalyzeInstaller("fixture".into()),
        O::AnalyzeProduct("fixture".into()),
        O::ThumbnailCleanup(vec![]),
        O::ComponentAnalysis,
        O::ComponentCleanup,
    ];
    for op in operations {
        for source in [op.label(), op.consequences()] {
            let en = text(false, source);
            assert!(
                !en.chars().any(|c| ('А'..='я').contains(&c)),
                "Untranslated caption: {en}"
            );
            assert_eq!(text(true, source), source);
        }
    }
}
