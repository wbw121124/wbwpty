//! Hand written Win32 FFI for the injected DLL.
//!
//! The DLL is `#![no_std]`, so we cannot use `windows-sys` (it drags in the
//! generated `windows-targets` machinery and pulls `std` feature surfaces we do
//! not need). Everything below mirrors the declarations from the Windows SDK
//! headers (`WinBase.h`, `fileapi.h`, `consoleapi.h`, `synchapi.h`,
//! `threadpoolapiset.h`) one-to-one, keeping the exact `BOOL`/`HANDLE`
//! semantics: we need `GetLastError()` right after every call.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::ffi::c_void;

pub type BOOL = i32;
pub type BOOLEAN = u8;
pub type BYTE = u8;
pub type WORD = u16;
pub type DWORD = u32;
pub type LONG = i32;
pub type USHORT = u16;
pub type ULONGLONG = u64;
pub type NTSTATUS = i32;

pub type HANDLE = *mut c_void;
pub type HINSTANCE = *mut c_void;
pub type HMODULE = *mut c_void;
pub type LPVOID = *mut c_void;
pub type LPCVOID = *const c_void;
pub type LPWSTR = *mut u16;
pub type LPCWSTR = *const u16;
pub type LPSTR = *mut u8;
pub type LPCSTR = *const u8;
pub type LPDWORD = *mut DWORD;
pub type LPBOOL = *mut BOOL;
pub type LPTHREAD_START_ROUTINE = Option<unsafe extern "system" fn(*mut c_void) -> DWORD>;
pub type FARPROC = Option<unsafe extern "system" fn() -> isize>;

pub const FALSE: BOOL = 0;
pub const TRUE: BOOL = 1;

pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

pub const STD_INPUT_HANDLE: DWORD = 0xffff_fffe;
pub const STD_OUTPUT_HANDLE: DWORD = 0xffff_ffff;
pub const STD_ERROR_HANDLE: DWORD = 0xffff_fffd;

pub const GENERIC_READ: DWORD = 0x8000_0000;
pub const GENERIC_WRITE: DWORD = 0x4000_0000;
pub const FILE_SHARE_READ: DWORD = 0x0000_0001;
pub const FILE_SHARE_WRITE: DWORD = 0x0000_0002;
pub const OPEN_EXISTING: DWORD = 3;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x0000_0080;
pub const FILE_FLAG_OVERLAPPED: DWORD = 0x4000_0000;
pub const HANDLE_FLAG_INHERIT: DWORD = 0x0000_0001;

pub const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_TIMEOUT: DWORD = 0x0000_0102;
pub const INFINITE: DWORD = 0xffff_ffff;

pub const ERROR_FILE_NOT_FOUND: DWORD = 2;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_INVALID_HANDLE: DWORD = 6;
pub const ERROR_BROKEN_PIPE: DWORD = 109;
pub const ERROR_PIPE_BUSY: DWORD = 231;
pub const ERROR_HANDLE_EOF: DWORD = 38;
pub const ERROR_OPERATION_ABORTED: DWORD = 995;
pub const ERROR_IO_PENDING: DWORD = 997;

pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

pub const DLL_PROCESS_DETACH: DWORD = 0;
pub const DLL_PROCESS_ATTACH: DWORD = 1;
pub const DLL_THREAD_ATTACH: DWORD = 2;
pub const DLL_THREAD_DETACH: DWORD = 3;

// Process creation flags (winbase.h).
pub const DETACHED_PROCESS: DWORD = 0x0000_0008;
pub const CREATE_NEW_CONSOLE: DWORD = 0x0000_0010;
pub const CREATE_NO_WINDOW: DWORD = 0x0800_0000;
pub const STARTF_USESTDHANDLES: DWORD = 0x0000_0100;

pub const COORD_CHAR: u16 = 0xfffe;

// Console input/output modes (wincon.h).
pub const ENABLE_PROCESSED_INPUT: DWORD = 0x0001;
pub const ENABLE_LINE_INPUT: DWORD = 0x0002;
pub const ENABLE_ECHO_INPUT: DWORD = 0x0004;
pub const ENABLE_WINDOW_INPUT: DWORD = 0x0008;
pub const ENABLE_MOUSE_INPUT: DWORD = 0x0010;
pub const ENABLE_INSERT_MODE: DWORD = 0x0020;
pub const ENABLE_QUICK_EDIT_MODE: DWORD = 0x0040;
pub const ENABLE_EXTENDED_FLAGS: DWORD = 0x0080;
pub const ENABLE_AUTO_POSITION: DWORD = 0x0100;
pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: DWORD = 0x0004;
pub const ENABLE_PROCESSED_OUTPUT: DWORD = 0x0001;

// Input record types (wincon.h KEY_EVENT_RECORD::uChar/uControlKeyState).
pub const KEY_EVENT: u16 = 0x0001;
pub const MOUSE_EVENT: u16 = 0x0002;
pub const WINDOW_EVENT: u16 = 0x0004;
pub const MENU_EVENT: u16 = 0x0008;
pub const FOCUS_EVENT: u16 = 0x0010;

pub const LEFT_ALT_PRESSED: DWORD = 0x0001;
pub const LEFT_CTRL_PRESSED: DWORD = 0x0002;
pub const RIGHT_ALT_PRESSED: DWORD = 0x0004;
pub const RIGHT_CTRL_PRESSED: DWORD = 0x0008;
pub const SHIFT_PRESSED: DWORD = 0x0010;

pub const VK_BACK: u16 = 0x08;
pub const VK_TAB: u16 = 0x09;
pub const VK_RETURN: u16 = 0x0d;
pub const VK_ESCAPE: u16 = 0x1b;
pub const VK_SPACE: u16 = 0x20;
pub const VK_END: u16 = 0x23;
pub const VK_HOME: u16 = 0x24;
pub const VK_LEFT: u16 = 0x25;
pub const VK_UP: u16 = 0x26;
pub const VK_RIGHT: u16 = 0x27;
pub const VK_DOWN: u16 = 0x28;
pub const VK_INSERT: u16 = 0x2d;
pub const VK_DELETE: u16 = 0x2e;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct COORD {
    pub X: i16,
    pub Y: i16,
}

/// `STARTUPINFOW` (winbase.h).
///
/// Only the fields the payload writes are named; the rest are present so the
/// offsets after them are right, which is the whole point of mirroring the
/// layout rather than taking a pointer to something opaque.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STARTUPINFOW {
    pub cb: DWORD,
    pub lpReserved: LPWSTR,
    pub lpDesktop: LPWSTR,
    pub lpTitle: LPWSTR,
    pub dwX: DWORD,
    pub dwY: DWORD,
    pub dwXSize: DWORD,
    pub dwYSize: DWORD,
    pub dwXCountChars: DWORD,
    pub dwYCountChars: DWORD,
    pub dwFillAttribute: DWORD,
    pub dwFlags: DWORD,
    pub wShowWindow: WORD,
    pub cbReserved2: WORD,
    pub lpReserved2: *mut u8,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

/// `PROCESS_INFORMATION` (winbase.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
}

// x64: four `ULONG`s precede `ConsoleHandle` in `RTL_USER_PROCESS_PARAMETERS`,
// which pads to the first 8-byte slot at 0x10. Source: ReactOS `ntpsapi.h`.
const _: () = assert!(core::mem::offset_of!(STARTUPINFOW, dwFlags) == 0x3c);
const _: () = assert!(core::mem::offset_of!(STARTUPINFOW, hStdInput) == 0x50);
const _: () = assert!(core::mem::offset_of!(STARTUPINFOW, hStdOutput) == 0x58);
const _: () = assert!(core::mem::offset_of!(STARTUPINFOW, hStdError) == 0x60);
const _: () = assert!(core::mem::size_of::<STARTUPINFOW>() == 0x68);
const _: () = assert!(core::mem::size_of::<PROCESS_INFORMATION>() == 0x18);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SMALL_RECT {
    pub Left: i16,
    pub Top: i16,
    pub Right: i16,
    pub Bottom: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CONSOLE_SCREEN_BUFFER_INFO {
    pub dwSize: COORD,
    pub dwCursorPosition: COORD,
    pub wAttributes: WORD,
    pub srWindow: SMALL_RECT,
    pub dwMaximumWindowSize: COORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CONSOLE_CURSOR_INFO {
    pub dwSize: DWORD,
    pub bVisible: BOOL,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KEY_EVENT_RECORD {
    pub bKeyDown: BOOL,
    pub wRepeatCount: WORD,
    pub wVirtualKeyCode: WORD,
    pub wVirtualScanCode: WORD,
    pub uChar: u16,
    pub uControlKeyState: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MOUSE_EVENT_RECORD {
    pub dwMousePosition: COORD,
    pub dwButtonState: DWORD,
    pub dwControlKeyState: DWORD,
    pub dwEventFlags: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINDOW_EVENT_RECORD {
    pub dwSize: DWORD,
    pub dwConsoleWindowInfo: BOOL,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union EVENT_UNION {
    pub KeyEvent: KEY_EVENT_RECORD,
    pub MouseEvent: MOUSE_EVENT_RECORD,
    pub WindowEvent: WINDOW_EVENT_RECORD,
    pub FocusEvent: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct INPUT_RECORD {
    pub EventType: WORD,
    pub uChar: u16,
    pub Event: EVENT_UNION,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Offset: DWORD,
    pub OffsetHigh: DWORD,
    pub hEvent: HANDLE,
}

extern "system" {
    // kernel32
    pub fn GetLastError() -> DWORD;
    pub fn SetLastError(dwErrCode: DWORD) -> DWORD;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn DuplicateHandle(
        hSourceProcessHandle: HANDLE,
        hSourceHandle: HANDLE,
        hTargetProcessHandle: HANDLE,
        lpTargetHandle: LPDWORD,
        dwDesiredAccess: DWORD,
        bInheritHandle: BOOL,
        dwOptions: DWORD,
    ) -> BOOL;
    pub fn CreateThread(
        lpThreadAttributes: LPVOID,
        dwStackSize: usize,
        lpStartAddress: LPTHREAD_START_ROUTINE,
        lpParameter: LPVOID,
        dwCreationFlags: DWORD,
        lpThreadId: LPDWORD,
    ) -> HANDLE;
    pub fn GetCurrentThread() -> HANDLE;
    pub fn ResumeThread(hThread: HANDLE) -> DWORD;
    pub fn SuspendThread(hThread: HANDLE) -> DWORD;
    pub fn GetExitCodeThread(hThread: HANDLE, lpExitCode: LPDWORD) -> BOOL;
    pub fn Sleep(dwMilliseconds: DWORD);
    pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
    pub fn GetCurrentProcessId() -> DWORD;
    pub fn GetModuleHandleW(lpModuleName: LPCWSTR) -> HMODULE;
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) -> FARPROC;
    pub fn LoadLibraryW(lpLibFileName: LPCWSTR) -> HMODULE;
    pub fn VirtualProtect(
        lpAddress: LPVOID,
        dwSize: usize,
        flNewProtect: DWORD,
        lpflOldProtect: LPDWORD,
    ) -> BOOL;
    pub fn SetHandleInformation(hObject: HANDLE, dwMask: DWORD, dwFlags: DWORD) -> BOOL;
    pub fn SetStdHandle(nStdHandle: DWORD, hHandle: HANDLE) -> BOOL;
    pub fn GetStdHandle(nStdHandle: DWORD) -> HANDLE;
    pub fn GetEnvironmentVariableW(lpName: LPCWSTR, lpBuffer: LPWSTR, nSize: DWORD) -> DWORD;
    pub fn GetModuleFileNameW(hModule: HMODULE, lpFilename: LPWSTR, nSize: DWORD) -> DWORD;

    // kernel32 (fileapi)
    pub fn CreateFileW(
        lpFileName: LPCWSTR,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: LPVOID,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;

    // kernel32 (fileapi / winbase)
    pub fn ReadFile(
        hFile: HANDLE,
        lpBuffer: LPVOID,
        nNumberOfBytesToRead: DWORD,
        lpNumberOfBytesRead: LPDWORD,
        lpOverlapped: *mut OVERLAPPED,
    ) -> BOOL;
    pub fn WriteFile(
        hFile: HANDLE,
        lpBuffer: LPCVOID,
        nNumberOfBytesToWrite: DWORD,
        lpNumberOfBytesWritten: LPDWORD,
        lpOverlapped: *mut OVERLAPPED,
    ) -> BOOL;
    pub fn CreateEventW(
        lpEventAttributes: LPVOID,
        bManualReset: BOOL,
        bInitialState: BOOL,
        lpName: LPCWSTR,
    ) -> HANDLE;
    pub fn CreateEventA(
        lpEventAttributes: LPVOID,
        bManualReset: BOOL,
        bInitialState: BOOL,
        lpName: LPCSTR,
    ) -> HANDLE;
    pub fn CancelIoEx(hFile: HANDLE, lpOverlapped: *mut OVERLAPPED) -> BOOL;
    pub fn CancelIo(hFile: HANDLE) -> BOOL;

    // kernel32 (synchapi)
    pub fn WaitForMultipleObjects(
        nCount: DWORD,
        lpHandles: *const HANDLE,
        bWaitAll: BOOL,
        dwMilliseconds: DWORD,
    ) -> DWORD;

    // kernel32 (consoleapi)
    pub fn AllocConsole() -> BOOL;
    pub fn FreeConsole() -> BOOL;
    pub fn AttachConsole(dwProcessId: DWORD) -> BOOL;
    pub fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: LPDWORD) -> BOOL;
    pub fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) -> BOOL;
    pub fn GetConsoleScreenBufferInfo(
        hConsoleOutput: HANDLE,
        lpConsoleScreenBufferInfo: *mut CONSOLE_SCREEN_BUFFER_INFO,
    ) -> BOOL;
    pub fn GetConsoleScreenBufferInfoEx(
        hConsoleOutput: HANDLE,
        lpConsoleScreenBufferInfo: *mut usize,
    ) -> BOOL;
    pub fn SetConsoleCursorPosition(hConsoleOutput: HANDLE, dwCursorPosition: COORD) -> BOOL;
    pub fn GetConsoleCursorInfo(hConsoleOutput: HANDLE, lpConsoleCursorInfo: *mut CONSOLE_CURSOR_INFO) -> BOOL;
    pub fn SetConsoleCursorInfo(hConsoleOutput: HANDLE, lpConsoleCursorInfo: *mut CONSOLE_CURSOR_INFO) -> BOOL;
    pub fn WriteConsoleW(
        hConsoleOutput: HANDLE,
        lpBuffer: LPCVOID,
        nNumberOfCharsToWrite: DWORD,
        lpNumberOfCharsWritten: LPDWORD,
        lpReserved: LPVOID,
    ) -> BOOL;
    pub fn WriteConsoleA(
        hConsoleOutput: HANDLE,
        lpBuffer: LPCVOID,
        nNumberOfCharsToWrite: DWORD,
        lpNumberOfCharsWritten: LPDWORD,
        lpReserved: LPVOID,
    ) -> BOOL;
    pub fn ReadConsoleW(
        hConsoleInput: HANDLE,
        lpBuffer: LPVOID,
        nNumberOfCharsToRead: DWORD,
        lpNumberOfCharsRead: LPDWORD,
        pInputControl: LPVOID,
    ) -> BOOL;
    pub fn ReadConsoleA(
        hConsoleInput: HANDLE,
        lpBuffer: LPVOID,
        nNumberOfCharsToRead: DWORD,
        lpNumberOfCharsRead: LPDWORD,
        pInputControl: LPVOID,
    ) -> BOOL;
    pub fn ReadConsoleInputW(
        hConsoleInput: HANDLE,
        lpBuffer: *mut INPUT_RECORD,
        nNumberOfEventsToRead: DWORD,
        lpNumberOfEventsRead: LPDWORD,
        pInputControl: LPVOID,
    ) -> BOOL;
    pub fn WriteConsoleInputW(
        hConsoleInput: HANDLE,
        lpBuffer: *const INPUT_RECORD,
        nNumberOfEventsToWrite: DWORD,
        lpNumberOfEventsWritten: LPDWORD,
    ) -> BOOL;
    pub fn GetNumberOfConsoleInputEvents(hConsoleInput: HANDLE, lpNumberOfEvents: LPDWORD) -> BOOL;
    pub fn GetConsoleCP() -> u32;
    pub fn SetConsoleCP(wCodePageId: u32) -> BOOL;
    pub fn GetConsoleOutputCP() -> u32;
    pub fn SetConsoleOutputCP(wCodePageId: u32) -> BOOL;
    pub fn GetConsoleTitleW(lpConsoleTitle: LPWSTR, nSize: DWORD) -> DWORD;
    pub fn SetConsoleTitleW(lpConsoleTitle: LPCWSTR) -> BOOL;
    pub fn GetConsoleWindow() -> HANDLE;
    pub fn FlushConsoleInputBuffer(hConsoleInput: HANDLE) -> BOOL;

    // ntdll
    pub fn RtlNtStatusToDosError(Status: NTSTATUS) -> DWORD;

    // kernel32 (debugapi)
    pub fn OutputDebugStringA(lpOutputString: LPCSTR);
    pub fn IsDebuggerPresent() -> BOOL;
}