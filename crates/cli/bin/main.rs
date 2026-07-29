//! `asbx` process entrypoint.

#![forbid(unsafe_code)]

use std::process::ExitCode;

mod app;
mod debugger;

fn main() -> ExitCode {
    app::entry()
}
