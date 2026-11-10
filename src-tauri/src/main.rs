// Release builds on Windows are GUI-subsystem binaries: no console window opens next to
// the app. Debug builds keep the console for `make dev` logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    mooring_app_lib::run();
}
