![WinStateDiag](assets/github-header.png)

# WinStateDiag
**Windows State Diagnostics**

Development status: in progress / В разработке

---

## EN

WinStateDiag is a portable read-only diagnostic center for Windows 10/11 x64. It collects Windows diagnostic information and hardware inventory and automatically packages the results into a ZIP report in the Reports folder. The ZIP can then be transferred to an AI system for deeper analysis and interpretation of the computer's current state.

**Key features**
- Windows diagnostics
- Hardware Report
- Read-only approach
- Portable operation (no installation)
- Automatic ZIP report
- AI-ready report format

## RU

WinStateDiag — портативный диагностический центр только для чтения для Windows 10/11 x64. Он собирает диагностическую информацию Windows и сведения об оборудовании и автоматически упаковывает результаты в ZIP-отчёт в папке Reports. Полученный ZIP можно передать нейросети для углублённого анализа и понимания текущего состояния компьютера.

**Ключевые возможности**
- Диагностика Windows
- Hardware Report (аппаратный паспорт)
- Подход только для чтения (read-only)
- Портативная работа без установки
- Автоматический ZIP-отчёт
- Формат отчёта, готовый для передачи нейросети

## Supported OS / Поддерживаемые ОС

- Windows 10 x64
- Windows 11 x64

## How it works / Схема работы

```
Windows PC
    ↓
WinStateDiag
    ↓
System Diagnostics + Hardware Report
    ↓
Reports\<date>\<session>.zip
    ↓
AI / Neural Network
    ↓
Deep technical analysis
```

WinStateDiag does not perform AI analysis itself at this stage — it produces a portable ZIP with diagnostic information.
WinStateDiag на текущем этапе не выполняет AI-анализ сам — он формирует переносимый ZIP с диагностической информацией.

## Diagnostic modes / Режимы диагностики

1. **Standard / Основной** — automatic diagnostics; SFC / DISM / CHKDSK deep checks are OFF.
2. **Custom Deep Checks / Выбор глубоких проверок** — standard diagnostics plus a one-time selection of additional read-only checks: `SFC /verifyonly`, `DISM /Online /Cleanup-Image /ScanHealth`, `CHKDSK <SystemDrive> /scan`.
3. **Full / Полный** — automatically runs standard diagnostics and all three deep read-only checks.

## Hardware Report

Hardware Report is a hardware passport/inventory module: System, Motherboard, BIOS/UEFI, CPU, RAM, Storage, GPU, Network, Battery (where available). It is packaged automatically into the diagnostic archive.

## Reports

```
WinStateDiag.exe
Reports\
└── DD-MM-YY\
    └── <session>.zip
```

One diagnostic session = one ZIP. The `Reports` folder is not tracked in Git.

## Roadmap (planned, not implemented) / В планах (не реализовано)

An optional AI Analysis module with pluggable providers (ChatGPT, Claude, Gemini, Grok, DeepSeek, Qwen, local AI, custom) is planned for a future milestone — not implemented, not researched, no SDKs added yet. WinStateDiag stays fully useful without AI integration, through a plain ZIP report.

See [docs/ROADMAP.md](docs/ROADMAP.md).
