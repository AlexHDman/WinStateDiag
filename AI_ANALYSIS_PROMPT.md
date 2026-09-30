# WinStateDiag — AI Analysis Prompt

Use this prompt together with a diagnostic ZIP archive created by **EXPC WinStateDiag**.

---

## English

Analyze the attached diagnostic ZIP archive created by **EXPC WinStateDiag**.

### Analysis rules

- Inspect the **entire archive and all diagnostic evidence files**, not only one summary or report.
- Start with `manifest.json` when present and use it to understand the modules, evidence files, Windows build, timestamps and deep-check states.
- Correlate Windows events, drivers, devices, hardware data, storage data, SFC / DISM / CHKDSK results, application errors, WHEA, BSOD/shutdown information and timestamps across files.
- Distinguish:
  - current and repeatable problems;
  - historical events that are no longer active;
  - informational or normal Windows noise;
  - findings that require additional verification.
- Do **not** treat the presence of an Event Viewer error as proof of a current fault without supporting evidence.
- Consider frequency, first/last occurrence and whether multiple independent sources confirm the same problem.
- Do not invent missing information or assume a cause that is not supported by the archive.
- For every significant conclusion, state **which file, section, device, event or other evidence supports it**.
- Do not recommend reinstalling Windows, mass driver replacement, registry cleaners, debloat tools or other broad repair actions without concrete diagnostic evidence.
- WinStateDiag is a read-only diagnostic tool. Treat suggested repair commands shown in reports as recommendations, not as actions already performed.

### Output

Give the result in this order:

1. **Critical / likely problems**
2. **Needs verification**
3. **Non-critical / historical / ignorable findings**
4. **Recommended next checks or actions**

Finish with a concise summary:

**Finding → importance → evidence → recommended next step**

Prioritize evidence and practical troubleshooting over generic Windows advice.

---

## Русский

Проанализируй приложенный диагностический ZIP-архив, созданный **EXPC WinStateDiag**.

### Правила анализа

- Изучи **весь архив и все диагностические файлы**, а не только один итоговый отчёт.
- При наличии `manifest.json` начни с него: используй его для понимания состава модулей, файлов доказательств, версии Windows, времени запуска и результатов глубоких проверок.
- Сопоставляй между собой события Windows, драйверы, устройства, оборудование, накопители, результаты SFC / DISM / CHKDSK, ошибки приложений, WHEA, BSOD/аварийные завершения и временные метки.
- Разделяй:
  - актуальные и повторяющиеся проблемы;
  - старые события, которые больше не проявляются;
  - информационные сообщения и обычный системный шум Windows;
  - находки, требующие дополнительной проверки.
- Не считай наличие ошибки в журнале событий доказательством текущей неисправности без подтверждающих данных.
- Учитывай частоту, первое/последнее появление события и наличие подтверждения из нескольких независимых источников.
- Не выдумывай отсутствующие сведения и не назначай причину без подтверждения данными архива.
- Для каждого существенного вывода указывай, **какой файл, раздел, устройство, событие или другое доказательство его подтверждает**.
- Не предлагай переустановку Windows, массовую замену драйверов, чистильщики реестра, debloat-инструменты или другие широкие вмешательства без конкретных диагностических оснований.
- WinStateDiag работает преимущественно в режиме только чтения. Команды восстановления, показанные в отчётах, считай рекомендациями, а не уже выполненными действиями.

### Формат ответа

Дай результат в таком порядке:

1. **Критические / вероятные проблемы**
2. **Требует дополнительной проверки**
3. **Несущественные / старые / допустимые события**
4. **Что проверить или сделать дальше**

В конце дай краткий итог:

**Что обнаружено → важность → доказательство → следующий шаг**

Приоритет — фактическим данным отчёта и практической диагностике, а не общим советам по Windows.
