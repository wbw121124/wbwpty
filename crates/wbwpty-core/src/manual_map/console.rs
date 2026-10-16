//! Pointing the target's console API imports at the payload.
//!
//! This is [`super::hook`] with a different table. The mechanism, the reasoning
//! and the coverage limit are the same, so they are not repeated:
//!
//! * an IAT slot is data, so a Control Flow Guard image never inspects it;
//! * a program that resolves the API at runtime with `GetProcAddress` has no
//!   slot for it and is therefore not intercepted.
//!
//! What is here is the list, and the fact that a list is more than one slot.
//!
//! # Each API needs its own substitute address
//!
//! [`super::hook`] publishes the address of one function and rewrites one slot.
//! Here there are eight, and the host has to know which export answers which
//! Win32 name. That mapping is [`CONSOLE_APIS`], and it is duplicated on the
//! payload side as the signature of each `wbwpty_*` substitute: the host matches
//! the pair, the payload matches the signature. Neither can check the other, so
//! the test that would catch a mismatch is
//! [`crate::manual_map::console::tests::the_substitute_is_exported_by_the_payload`].
//!
//! # Not every console API is intercepted
//!
//! The ones left alone are the ones that need a *screen*: `GetConsoleScreenBufferInfo`
//! and its family want a cursor position and a cell grid. The grid needs a heap,
//! this DLL has none (AGENTS rule 3), so the screen lives in the host and
//! answering would mean a round trip. Until that exists, leaving them alone fails
//! honestly; substituting from an invented cursor position would fail confusingly.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::manual_map::iat;
use crate::manual_map::remote::RemoteProcess;
use crate::manual_map::InjectionReport;

/// One intercepted console API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleApi {
    /// The name as it appears in the target's import table.
    pub win32_name: &'static str,
    /// The payload's substitute for it.
    pub export: &'static str,
}

/// The intercepted set, in a fixed order.
///
/// Order is part of the contract with the test above but not with the payload:
/// the host resolves each substitute by name, so a reordering here is harmless
/// as long as the pairs stay together.
pub const CONSOLE_APIS: &[ConsoleApi] = &[
    ConsoleApi {
        win32_name: "GetConsoleMode",
        export: "wbwpty_get_console_mode",
    },
    ConsoleApi {
        win32_name: "SetConsoleMode",
        export: "wbwpty_set_console_mode",
    },
    ConsoleApi {
        win32_name: "WriteConsoleW",
        export: "wbwpty_write_console_w",
    },
    ConsoleApi {
        win32_name: "WriteConsoleA",
        export: "wbwpty_write_console_a",
    },
    ConsoleApi {
        win32_name: "GetConsoleScreenBufferInfo",
        export: "wbwpty_get_console_screen_buffer_info",
    },
    ConsoleApi {
        win32_name: "GetConsoleCursorInfo",
        export: "wbwpty_get_console_cursor_info",
    },
    ConsoleApi {
        win32_name: "GetConsoleWindow",
        export: "wbwpty_get_console_window",
    },
    ConsoleApi {
        win32_name: "SetConsoleTextAttribute",
        export: "wbwpty_set_console_text_attribute",
    },
    ConsoleApi {
        win32_name: "GetConsoleTextAttribute",
        export: "wbwpty_get_console_text_attribute",
    },
    ConsoleApi {
        win32_name: "AllocConsole",
        export: "wbwpty_alloc_console",
    },
    ConsoleApi {
        win32_name: "FreeConsole",
        export: "wbwpty_free_console",
    },
    ConsoleApi {
        win32_name: "AttachConsole",
        export: "wbwpty_attach_console",
    },
];

/// What the substitution did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleHookReport {
    /// Win32 name → the payload export it now points at, for the slots rewritten.
    pub installed: Vec<(String, u64)>,
    /// Win32 names the target imports but that were left alone.
    ///
    /// An empty list here with an empty [`Self::installed`] means the target uses
    /// no console API at all, which is the common case and not a problem.
    pub not_intercepted: Vec<String>,
    /// True when at least one image page had to be made writable first.
    pub needed_protection_change: bool,
}

/// Substitutes the payload for the target's console API.
///
/// Returns `Ok(None)` when the target imports none of them, which is a
/// legitimate answer: a program that never calls the console API has nothing to
/// substitute, and that is most programs.
///
/// `report` is the payload's own injection report - the substitutes live inside
/// the mapped image, so the substitution cannot come before it.
pub fn install_console_hook(
    proc: &RemoteProcess,
    target_image: &[u8],
    payload_dll: &Path,
    report: &InjectionReport,
) -> Result<Option<ConsoleHookReport>> {
    let payload = std::fs::read(payload_dll)
        .with_context(|| format!("reading the payload {}", payload_dll.display()))?;
    let substitute_of = |name: &str| -> Result<u64> {
        let rva = crate::manual_map::find_export_rva(&payload, name)
            .with_context(|| format!("looking up the payload export {name}"))?
            .with_context(|| format!("the payload does not export {name}"))?;
        Ok(report.image_base + rva as u64)
    };

    let wanted: Vec<&str> = CONSOLE_APIS.iter().map(|a| a.win32_name).collect();
    let slots = iat::find_imports(target_image, &wanted)
        .context("walking the target's console imports")?;
    if slots.is_empty() {
        return Ok(None);
    }

    let base = proc.image_base()?;
    let mut installed = Vec::new();
    let mut not_intercepted = Vec::new();
    let mut needed_protection_change = false;

    for slot in &slots {
        let Some(api) = CONSOLE_APIS.iter().find(|a| a.win32_name == slot.symbol) else {
            not_intercepted.push(slot.symbol.clone());
            continue;
        };
        let address = slot.address(base);
        let substitute = substitute_of(api.export)?;

        match write_slot(proc, address, substitute, &mut needed_protection_change) {
            Ok(()) => installed.push((slot.symbol.clone(), substitute)),
            Err(err) => {
                // One unwritable slot does not condemn the rest, and the API it
                // answers is simply not available to the target.
                not_intercepted.push(format!("{} ({err:#})", slot.symbol));
            }
        }
    }

    if installed.is_empty() {
        return Ok(None);
    }
    Ok(Some(ConsoleHookReport {
        installed,
        not_intercepted,
        needed_protection_change,
    }))
}

/// Rewrites one slot, making its page writable if the image says otherwise.
fn write_slot(
    proc: &RemoteProcess,
    address: u64,
    substitute: u64,
    needed_protection_change: &mut bool,
) -> Result<()> {
    if let Err(err) = proc.write_bytes(address, &substitute.to_le_bytes()) {
        // The loader leaves `.idata` writable in practice, but "in practice" is
        // not something to write a substitution on top of.
        proc.protect(address, 8, windows_sys::Win32::System::Memory::PAGE_READWRITE)
            .with_context(|| format!("making an import slot writable: {err:#}"))?;
        proc.write_bytes(address, &substitute.to_le_bytes())
            .context("writing the substituted import slot")?;
        *needed_protection_change = true;
    }

    let readback = proc.read_bytes(address, 8)?;
    let readback = u64::from_le_bytes(readback.try_into().expect("read 8"));
    if readback != substitute {
        bail!("the import slot did not take: wrote {substitute:#x}, read {readback:#x}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payload has to export a substitute for every name the host looks for,
    /// and under exactly that name.
    ///
    /// Neither side can check this against the other: the host resolves by
    /// string, the payload is reached by signature, and a mismatch produces a
    /// rewrite to a name that does not exist rather than a compile error.
    #[test]
    fn the_substitute_is_exported_by_the_payload() {
        let Some(path) = payload_dll_path() else {
            eprintln!("skipping: wbwpty_redirect.dll not built yet");
            return;
        };
        let image = std::fs::read(&path).expect("read payload");
        for api in CONSOLE_APIS {
            assert!(
                crate::manual_map::find_export_rva(&image, api.export)
                    .expect("look up the export")
                    .is_some(),
                "the payload does not export {} for {}",
                api.export,
                api.win32_name
            );
        }
    }

    /// The stats word is how the host tells "the substitutes are installed and
    /// being called" from "installed and nothing calls them", which look identical
    /// from outside.
    #[test]
    fn the_payload_publishes_the_console_stats_word() {
        let Some(path) = payload_dll_path() else {
            eprintln!("skipping: wbwpty_redirect.dll not built yet");
            return;
        };
        let image = std::fs::read(&path).expect("read payload");
        assert!(crate::manual_map::find_export_rva(&image, "WBWPTY_CONSOLE_STATS")
            .expect("look up the export")
            .is_some());
    }

    /// The walk must see every descriptor, not stop at the first plausible module.
    ///
    /// `wbwpty-spawn-probe.exe` imports `GetConsoleMode` and
    /// `GetConsoleScreenBufferInfo` through **two separate import descriptors**
    /// that both name kernel32 - one contributed by the CRT, one by the probe's own
    /// `extern "system"` block. A walk that stops as soon as it has seen the module
    /// it was looking for would find the first and miss the second, and the
    /// symptom is indistinguishable from a target that does not use the console
    /// API: "the substitution installed nothing".
    ///
    /// Both are asserted found, in the same image, with distinct slots.
    #[test]
    fn the_walk_sees_every_kernel32_descriptor() {
        let Some(path) = probe_path() else {
            eprintln!("skipping: wbwpty-spawn-probe.exe not built yet");
            return;
        };
        let image = std::fs::read(&path).expect("read the probe");
        let wanted: Vec<&str> = CONSOLE_APIS.iter().map(|a| a.win32_name).collect();
        let found = iat::find_imports(&image, &wanted).expect("walk the probe's imports");

        let slot_of = |name: &str| {
            found
                .iter()
                .find(|s| s.symbol == name)
                .unwrap_or_else(|| {
                    panic!(
                        "the probe calls {name} but the walk did not find it; it found {:?}",
                        found.iter().map(|s| &s.symbol).collect::<Vec<_>>()
                    )
                })
                .clone()
        };

        let first = slot_of("GetConsoleMode");
        let second = slot_of("GetConsoleScreenBufferInfo");
        assert_ne!(
            first.iat_rva, second.iat_rva,
            "two imports of the same module must resolve to different slots"
        );

        // And the substitute has to be findable for what the probe *does* import,
        // because a slot with no substitute behind it is a silently dead rewrite.
        let substitute_of = |name: &str| {
            CONSOLE_APIS
                .iter()
                .find(|a| a.win32_name == name)
                .unwrap_or_else(|| panic!("{name} is not in the intercepted set"))
                .export
        };
        let payload = payload_image();
        for name in ["GetConsoleMode", "GetConsoleScreenBufferInfo", "WriteConsoleW"] {
            let export = substitute_of(name);
            assert!(
                crate::manual_map::find_export_rva(&payload, export)
                    .expect("look up the export")
                    .is_some(),
                "the payload does not export {export} for {name}"
            );
        }
    }

    fn payload_image() -> Vec<u8> {
        let Some(path) = payload_dll_path() else {
            return Vec::new();
        };
        std::fs::read(path).unwrap_or_default()
    }

    fn payload_dll_path() -> Option<std::path::PathBuf> {
        let exe = std::env::current_exe().ok()?;
        [
            exe.with_file_name("wbwpty_redirect.dll"),
            exe.parent()?.join("..").join("wbwpty_redirect.dll"),
        ]
        .into_iter()
        .find(|c| c.is_file())
    }

    fn probe_path() -> Option<std::path::PathBuf> {
        let exe = std::env::current_exe().ok()?;
        [
            exe.with_file_name("wbwpty-spawn-probe.exe"),
            exe.parent()?.join("..").join("wbwpty-spawn-probe.exe"),
        ]
        .into_iter()
        .find(|c| c.is_file())
    }
}