// WinStateDiag - portable Windows state diagnostic center (binary entry).
// Everything lives in the library crate (src/lib.rs); this file exists so the
// requireAdministrator manifest is linked into the shipped EXE only.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    win_state_diag::run()
}
