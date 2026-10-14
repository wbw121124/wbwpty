use anyhow::Result;
use clap::{CommandFactory, Parser};

/// Thin CLI front-end: argument parsing plus a wiring of the core session.
/// All of the actual work lives in `wbwpty_core`.

#[derive(Debug, Parser)]
#[command(
    name = "wbwpty",
    version,
    about = "ConPTY-free Windows terminal: manual-mapped DLL + named pipes",
    long_about = "Runs a console program with its stdio redirected onto wbwpty named pipes.\n\
                  No ConPTY, no winpty, no conhost.exe, no WSL, no SSH."
)]
struct Cli {
    /// Path to the injected redirect DLL (default: next to this executable).
    #[arg(long, value_name = "PATH")]
    dll: Option<std::path::PathBuf>,

    /// Print the conhost.exe process count before and after the run.
    #[arg(long)]
    dump_conhost: bool,

    /// Install the console API shim inside the target (default: on).
    #[arg(long)]
    shim: bool,

    /// Program and arguments to run, after `--`.
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<std::ffi::OsString>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.command.is_empty() {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    }

    println!(
        "wbwpty {} — pipeline stages land in later commits (dll={:?}, shim={})",
        env!("CARGO_PKG_VERSION"),
        cli.dll.as_deref().unwrap_or(std::path::Path::new("<default>")),
        cli.shim
    );

    Ok(())
}