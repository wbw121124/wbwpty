use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use wbwpty_core::child::ChildSpec;
use wbwpty_core::session::{Session, SessionConfig};

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

    /// Path the payload appends its diagnostics to (`WBWPTY_LOG`).
    #[arg(long, value_name = "PATH")]
    log: Option<std::path::PathBuf>,

    /// Report injection and shim decisions on stderr.
    #[arg(long, short)]
    verbose: bool,

    /// Skip mapping the payload DLL. stdio still works; only the console
    /// semantics (shim, ConsoleHandle sentinel) are lost.
    #[arg(long)]
    no_inject: bool,

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

    let conhost_before = cli.dump_conhost.then(conhost_count);

    let (program, args) = cli.command.split_first().expect("checked above");
    let spec = ChildSpec::new(program.clone()).args(args.iter().cloned());
    let config = SessionConfig {
        dll: cli.dll.clone(),
        log_path: cli.log.clone(),
        shim: cli.shim,
        inject: !cli.no_inject,
        verbose: cli.verbose,
        ..Default::default()
    };

    let session = Session::start(&spec, config).context("starting session")?;
    let pid = session.pid();

    let code = session.run_to_completion()?;

    if let Some(before) = conhost_before {
        let after = conhost_count();
        println!(
            "\n[wbwpty] pid {pid}: conhost.exe before={before} after={after} (delta {})",
            after as i64 - before as i64
        );
    }

    // Mirror the target's exit status the way a shell does.
    if code != 0 {
        std::process::exit(code as i32);
    }
    Ok(())
}

/// Number of live `conhost.exe` processes; the whole "no console host" claim
/// reduces to this staying put.
fn conhost_count() -> usize {
    wbwpty_core::inspect::conhost_count().unwrap_or(0)
}