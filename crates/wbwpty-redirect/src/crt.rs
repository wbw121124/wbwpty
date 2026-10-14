//! UCRT/Msvcrt standard stream repair.
//!
//! Filled in by the `feat(dll): repair and line-buffer the ucrt stdio streams`
//! stage. Only publicly exported CRT entry points may be used: on Windows 10
//! 17763 `ucrtbase.dll` does **not** export `__acrt_lowio_set_osfhandle` nor
//! `_setvbuf` (verified with `objdump -p` on this machine).