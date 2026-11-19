#[derive(Default)]
struct HardwareSupportState {
    operation: Option<crate::hardware_support::Operation>,
    rx: Option<Receiver<crate::hardware_support::Event>>,
    state: String,
    message: String,
    raw: String,
    initialized: bool,
}
impl WinStateDiagApp {
    fn start_hardware_support(&mut self, op: crate::hardware_support::Operation) {
        if self.hardware_support.rx.is_some() || self.sensors_rx.is_some() || self.powerlab.owns_reader() {
            return;
        }
        if op == crate::hardware_support::Operation::Install
            && !crate::hardware_support::can_install(&self.hardware_support.state)
        {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.hardware_support.rx = Some(rx);
        self.hardware_support.initialized = true;
        self.hardware_support.operation = Some(op);
        self.hardware_support.message = "Проверка аппаратного доступа…".into();
        let base = crate::app_paths::data_root(&std::env::current_exe().unwrap_or_default())
            .join("Logs")
            .join("HardwareSupport");
        crate::hardware_support::start(op, base, tx);
    }
    fn poll_hardware_support(&mut self) {
        if !self.hardware_support.initialized && !cfg!(test) && self.reference.is_none() {
            self.start_hardware_support(crate::hardware_support::Operation::Detect);
        }
        let event = self
            .hardware_support
            .rx
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(v) => Some(v),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    Some(crate::hardware_support::Event::Done(Err(
                        "Hardware observer disconnected".into(),
                    )))
                }
                Err(_) => None,
            });
        match event {
            Some(crate::hardware_support::Event::Progress(s)) => {
                let key = crate::hardware_support::field(&s, "stage");
                self.hardware_support.message = match if key.is_empty() {
                    s.as_str()
                } else {
                    key.as_str()
                } {
                    "Checking" => "Проверка PawnIO…",
                    "Preparing" => "Подготовка установки…",
                    "VerifyingFile" => "Проверка подписи и SHA256…",
                    "Installing" => "Установка PawnIO; ожидаем завершения…",
                    "VerifyingDriver" => "Проверка доступа к драйверу…",
                    "PreparingControl" => "Подготовка контрольного LHM…",
                    "ControlRunning" => "Контрольный LHM открыт; наше чтение приостановлено",
                    _ => "Операция с аппаратным источником…",
                }
                .into();
            }
            Some(crate::hardware_support::Event::Done(result)) => {
                self.hardware_support.rx = None;
                match result {
                    Ok(o) => {
                        self.hardware_support.message =
                            crate::hardware_support::label(&o.state).into();
                        if let Some(current) = o.dependency_state() {
                            self.hardware_support.state = current;
                        }
                        self.hardware_support.raw = o.raw;
                        push_journal(&mut self.journal, self.hardware_support.message.clone());
                        if o.reread || o.state=="INSTALLED_NOT_READY" {
                            if self.powerlab.open {self.powerlab.pending=true;} else {self.start_sensor_read(true);}
                        }
                    }
                    Err(e) => {
                        self.hardware_support.state = "ERROR".into();
                        self.hardware_support.message =
                            "Ошибка аппаратного доступа — см. журнал".into();
                        push_journal(&mut self.journal, format!("Hardware support: {e}"));
                    }
                }
            }
            None => {}
        }
    }
    fn hardware_support_vm(&self) -> crate::ui::vm::HardwareSupportVm {
        crate::ui::vm::HardwareSupportVm {
            message: if self.powerlab.owns_reader(){"Единый аппаратный опрос выполняется в PowerLab".into()}else{self.hardware_support.message.clone()},
            busy: self.hardware_support.rx.is_some()||self.powerlab.owns_reader(),
            can_install: crate::hardware_support::can_install(&self.hardware_support.state),
        }
    }
}
