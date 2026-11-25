#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, c_void};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::{HleExport, HleModule, hle_export};

const EINVAL: i32 = 22;

type Callback = extern "win64" fn();
type CallbackE = extern "win64" fn() -> i32;

mod c {
    use std::ffi::{c_char, c_int, c_void};

    unsafe extern "C" {
        pub fn realloc(block: *mut c_void, size: usize) -> *mut c_void;
        pub fn free(block: *mut c_void);
        pub fn strerror(code: c_int) -> *mut c_char;
        pub fn __errno_location() -> *mut c_int;
        pub fn _exit(code: c_int) -> !;
    }
}

#[repr(C)]
struct OnexitTable {
    first: *mut usize,
    last: *mut usize,
    end: *mut usize,
}

static ATEXIT: Mutex<Vec<usize>> = Mutex::new(Vec::new());
static INVALID_HANDLER: AtomicUsize = AtomicUsize::new(0);
static ARGC: AtomicI32 = AtomicI32::new(1);

extern "win64" fn _initialize_onexit_table(table: *mut OnexitTable) -> i32 {
    if table.is_null() {
        return -1;
    }
    // SAFETY: the title passes its own table.
    unsafe {
        table.write(OnexitTable {
            first: null_mut(),
            last: null_mut(),
            end: null_mut(),
        })
    };
    0
}

extern "win64" fn _register_onexit_function(table: *mut OnexitTable, function: usize) -> i32 {
    if table.is_null() {
        return -1;
    }
    // SAFETY: the title passes its own initialised table.
    let table = unsafe { &mut *table };
    let (len, capacity) = if table.first.is_null() {
        (0, 0)
    } else {
        // SAFETY: first <= last <= end inside one allocation made below.
        unsafe {
            (
                table.last.offset_from(table.first) as usize,
                table.end.offset_from(table.first) as usize,
            )
        }
    };
    if len == capacity {
        let new_capacity = (capacity * 2).max(4);
        // SAFETY: first is null or a block this function allocated.
        let block = unsafe { c::realloc(table.first.cast(), new_capacity * 8) }.cast::<usize>();
        if block.is_null() {
            return -1;
        }
        table.first = block;
        // SAFETY: `len <= new_capacity`, inside the block.
        unsafe {
            table.last = block.add(len);
            table.end = block.add(new_capacity);
        }
    }
    // SAFETY: `last < end`, inside the block.
    unsafe {
        table.last.write(function);
        table.last = table.last.add(1);
    }
    0
}

extern "win64" fn _execute_onexit_table(table: *mut OnexitTable) -> i32 {
    if table.is_null() {
        return -1;
    }
    // SAFETY: the title passes its own initialised table.
    let (first, mut last) = unsafe { ((*table).first, (*table).last) };
    // SAFETY: as above.
    unsafe {
        table.write(OnexitTable {
            first: null_mut(),
            last: null_mut(),
            end: null_mut(),
        })
    };
    while !first.is_null() && last > first {
        // SAFETY: `first < last`, inside the block the table owned.
        let function = unsafe {
            last = last.sub(1);
            last.read()
        };
        if function != 0 {
            // SAFETY: registered functions are `void (*)(void)` of the title.
            let function: Callback = unsafe { std::mem::transmute(function) };
            function();
        }
    }
    // SAFETY: the block was allocated by `_register_onexit_function` (or is null).
    unsafe { c::free(first.cast()) };
    0
}

extern "win64" fn _crt_atexit(function: usize) -> i32 {
    ATEXIT.lock().unwrap_or_else(|e| e.into_inner()).push(function);
    0
}

extern "win64" fn _crt_at_quick_exit(_function: usize) -> i32 {
    0
}

extern "win64" fn _cexit() {
    let functions = std::mem::take(&mut *ATEXIT.lock().unwrap_or_else(|e| e.into_inner()));
    for function in functions.into_iter().rev() {
        // SAFETY: registered functions are `void (*)(void)` of the title.
        let function: Callback = unsafe { std::mem::transmute(function) };
        function();
    }
}

extern "win64" fn _c_exit() {}

extern "win64" fn _exit(code: i32) -> ! {
    // SAFETY: ends the process without running host destructors, like the C library.
    unsafe { c::_exit(code) }
}

extern "win64" fn _initterm(first: *const usize, last: *const usize) {
    let mut at = first;
    while at < last {
        // SAFETY: the title passes an array of function pointers from `first` to `last`.
        let function = unsafe { at.read() };
        if function != 0 {
            // SAFETY: the entries are `void (*)(void)` of the title.
            let function: Callback = unsafe { std::mem::transmute(function) };
            function();
        }
        // SAFETY: `at < last`.
        at = unsafe { at.add(1) };
    }
}

extern "win64" fn _initterm_e(first: *const usize, last: *const usize) -> i32 {
    let mut at = first;
    while at < last {
        // SAFETY: the title passes an array of function pointers from `first` to `last`.
        let function = unsafe { at.read() };
        if function != 0 {
            // SAFETY: the entries are `int (*)(void)` of the title.
            let function: CallbackE = unsafe { std::mem::transmute(function) };
            let status = function();
            if status != 0 {
                return status;
            }
        }
        // SAFETY: `at < last`.
        at = unsafe { at.add(1) };
    }
    0
}

extern "win64" fn _errno() -> *mut i32 {
    // SAFETY: errno is thread-local and always valid.
    unsafe { c::__errno_location() }
}

extern "win64" fn _get_errno(out: *mut i32) -> i32 {
    if out.is_null() {
        return EINVAL;
    }
    // SAFETY: `out` is the title's out-parameter; errno is always valid.
    unsafe { out.write(c::__errno_location().read()) };
    0
}

extern "win64" fn _set_errno(value: i32) -> i32 {
    // SAFETY: errno is thread-local and always writable.
    unsafe { c::__errno_location().write(value) };
    0
}

extern "win64" fn __p___argc() -> *mut i32 {
    ARGC.as_ptr()
}

extern "win64" fn __p___argv() -> *mut usize {
    static CELL: OnceLock<usize> = OnceLock::new();
    *CELL.get_or_init(|| {
        let argv = Box::leak(Box::new([c"victory".as_ptr() as usize, 0usize]));
        (Box::leak(Box::new(argv.as_ptr() as usize)) as *mut usize) as usize
    }) as *mut usize
}

extern "win64" fn _configure_narrow_argv(_mode: i32) -> i32 {
    0
}

extern "win64" fn _initialize_narrow_environment() -> i32 {
    0
}

extern "win64" fn _get_narrow_winmain_command_line() -> *const c_char {
    c"".as_ptr()
}

extern "win64" fn _set_app_type(_kind: i32) {}

extern "win64" fn _register_thread_local_exe_atexit_callback(_callback: usize) {}

extern "win64" fn _set_invalid_parameter_handler(handler: usize) -> usize {
    INVALID_HANDLER.swap(handler, Ordering::SeqCst)
}

extern "win64" fn _invalid_parameter_noinfo() {
    match INVALID_HANDLER.load(Ordering::SeqCst) {
        0 => {
            eprintln!("VIctory: invalid parameter passed to a C runtime function");
            std::process::abort();
        }
        handler => {
            // SAFETY: the title registered a handler with the UCRT signature.
            let handler: extern "win64" fn(usize, usize, usize, u32, usize) =
                unsafe { std::mem::transmute(handler) };
            handler(0, 0, 0, 0, 0);
        }
    }
}

extern "win64" fn _invoke_watson(_: usize, _: usize, _: usize, _: u32, _: usize) -> ! {
    eprintln!("VIctory: the title invoked Watson (fatal runtime error)");
    std::process::abort();
}

fn wide(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the title passes a NUL-terminated wide string.
    unsafe {
        while text.add(len).read() != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    }
}

extern "win64" fn _wassert(message: *const u16, file: *const u16, line: u32) -> ! {
    eprintln!("VIctory: assertion failed: {} ({}:{line})", wide(message), wide(file));
    std::process::abort();
}

extern "win64" fn _seh_filter_exe(_code: u32, _pointers: *const c_void) -> i32 {
    0
}

extern "win64" fn _seh_filter_dll(_code: u32, _pointers: *const c_void) -> i32 {
    0
}

extern "win64" fn _set_new_mode(_mode: i32) -> i32 {
    0
}

extern "win64" fn _set_new_handler(_handler: usize) -> usize {
    0
}

extern "win64" fn _callnewh(_size: usize) -> i32 {
    0
}

extern "win64" fn strerror(code: i32) -> *mut c_char {
    // SAFETY: the C library returns a pointer to a static message.
    unsafe { c::strerror(code) }
}

pub fn module() -> HleModule {
    HleModule {
        name: "crt-runtime",
        dlls: &["api-ms-win-crt-runtime-*", "api-ms-win-crt-heap-*"],
        exports: vec![
            hle_export!(_initialize_onexit_table),
            hle_export!(_register_onexit_function),
            hle_export!(_execute_onexit_table),
            hle_export!(_crt_atexit),
            hle_export!(_crt_at_quick_exit),
            hle_export!(_cexit),
            hle_export!(_c_exit),
            hle_export!(_exit),
            hle_export!(_initterm),
            hle_export!(_initterm_e),
            hle_export!(_errno),
            hle_export!(_get_errno),
            hle_export!(_set_errno),
            hle_export!(__p___argc),
            hle_export!(__p___argv),
            hle_export!(_configure_narrow_argv),
            hle_export!(_initialize_narrow_environment),
            hle_export!(_get_narrow_winmain_command_line),
            hle_export!(_set_app_type),
            hle_export!(_register_thread_local_exe_atexit_callback),
            hle_export!(_set_invalid_parameter_handler),
            hle_export!(_invalid_parameter_noinfo),
            hle_export!(_invoke_watson),
            hle_export!(_wassert),
            hle_export!(_seh_filter_exe),
            hle_export!(_seh_filter_dll),
            hle_export!(_set_new_mode),
            hle_export!(_set_new_handler),
            hle_export!(_callnewh),
            hle_export!(strerror),
        ],
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;
    use std::sync::Mutex;

    use victory_loader::{ImportResolver, Resolution};
    use victory_pe::ImportSymbol;

    use super::OnexitTable;
    use crate::{HleResolver, HostPolicy};

    fn address(symbol: &str) -> usize {
        let name = ImportSymbol::Name {
            hint: 0,
            name: symbol.into(),
        };
        let resolver = HleResolver::new(HostPolicy::none());
        match resolver.resolve("api-ms-win-crt-runtime-l1-1-0.dll", &name) {
            Resolution::Found { address, .. } => address,
            Resolution::Missing => panic!("{symbol} is not resolved"),
        }
    }

    macro_rules! function {
        ($name:literal, $ty:ty) => {
            // SAFETY: the type is the signature the function was declared with.
            unsafe { std::mem::transmute::<usize, $ty>(address($name)) }
        };
    }

    static INIT: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static TABLE: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static EXIT: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    extern "win64" fn init_one() {
        INIT.lock().unwrap().push(1);
    }

    extern "win64" fn init_two() {
        INIT.lock().unwrap().push(2);
    }

    extern "win64" fn fails() -> i32 {
        7
    }

    extern "win64" fn never() -> i32 {
        INIT.lock().unwrap().push(99);
        0
    }

    extern "win64" fn table_one() {
        TABLE.lock().unwrap().push(1);
    }

    extern "win64" fn table_two() {
        TABLE.lock().unwrap().push(2);
    }

    extern "win64" fn exit_one() {
        EXIT.lock().unwrap().push(1);
    }

    extern "win64" fn exit_two() {
        EXIT.lock().unwrap().push(2);
    }

    #[test]
    fn initterm_runs_entries_in_order_and_stops_on_failure() {
        let initterm = function!("_initterm", extern "win64" fn(*const usize, *const usize));
        let initterm_e = function!(
            "_initterm_e",
            extern "win64" fn(*const usize, *const usize) -> i32
        );
        let table = [init_one as usize, 0, init_two as usize];
        initterm(table.as_ptr(), table.as_ptr().wrapping_add(table.len()));
        assert_eq!(*INIT.lock().unwrap(), [1, 2]);
        let table = [fails as usize, never as usize];
        let status = initterm_e(table.as_ptr(), table.as_ptr().wrapping_add(table.len()));
        assert_eq!(status, 7);
        assert_eq!(*INIT.lock().unwrap(), [1, 2]);
    }

    #[test]
    fn onexit_tables_grow_and_run_in_reverse() {
        let register = function!(
            "_register_onexit_function",
            extern "win64" fn(*mut OnexitTable, usize) -> i32
        );
        let execute = function!(
            "_execute_onexit_table",
            extern "win64" fn(*mut OnexitTable) -> i32
        );
        let initialize = function!(
            "_initialize_onexit_table",
            extern "win64" fn(*mut OnexitTable) -> i32
        );
        let mut table = OnexitTable {
            first: null_mut(),
            last: null_mut(),
            end: null_mut(),
        };
        assert_eq!(initialize(&mut table), 0);
        for _ in 0..3 {
            assert_eq!(register(&mut table, table_one as usize), 0);
            assert_eq!(register(&mut table, table_two as usize), 0);
        }
        assert_eq!(execute(&mut table), 0);
        assert_eq!(*TABLE.lock().unwrap(), [2, 1, 2, 1, 2, 1]);
        assert!(table.first.is_null());
    }

    #[test]
    fn errno_arguments_and_exit_functions_work() {
        let set_errno = function!("_set_errno", extern "win64" fn(i32) -> i32);
        let get_errno = function!("_get_errno", extern "win64" fn(*mut i32) -> i32);
        let errno = function!("_errno", extern "win64" fn() -> *mut i32);
        assert_eq!(set_errno(34), 0);
        let mut value = 0;
        assert_eq!(get_errno(&mut value), 0);
        assert_eq!(value, 34);
        // SAFETY: `_errno` returns a valid thread-local pointer.
        assert_eq!(unsafe { errno().read() }, 34);
        let argc = function!("__p___argc", extern "win64" fn() -> *mut i32);
        let argv = function!("__p___argv", extern "win64" fn() -> *mut usize);
        // SAFETY: both return pointers to process-wide variables.
        unsafe {
            assert_eq!(argc().read(), 1);
            assert_ne!(argv().read(), 0);
            assert_ne!((argv().read() as *const usize).read(), 0);
        }
        let atexit = function!("_crt_atexit", extern "win64" fn(usize) -> i32);
        let cexit = function!("_cexit", extern "win64" fn());
        assert_eq!(atexit(exit_one as usize), 0);
        assert_eq!(atexit(exit_two as usize), 0);
        cexit();
        assert_eq!(*EXIT.lock().unwrap(), [2, 1]);
    }
}
