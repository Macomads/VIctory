#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};

use crate::{HleExport, HleModule, hle_export};

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const STRUNCATE: i32 = 80;

type Compare = extern "win64" fn(*const c_void, *const c_void) -> i32;

macro_rules! passthrough {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        mod c {
            use super::*;

            unsafe extern "C" {
                $(pub fn $name($($arg: $ty),*) -> $ret;)*
            }
        }

        $(
            extern "win64" fn $name($($arg: $ty),*) -> $ret {
                // SAFETY: the title passes the arguments the C library documents.
                unsafe { c::$name($($arg),*) }
            }
        )*

        fn passthrough_exports() -> Vec<HleExport> {
            vec![$(hle_export!($name)),*]
        }
    };
}

passthrough! {
    malloc(size: usize) -> *mut c_void;
    calloc(count: usize, size: usize) -> *mut c_void;
    realloc(block: *mut c_void, size: usize) -> *mut c_void;
    free(block: *mut c_void) -> ();
    strlen(text: *const c_char) -> usize;
    strcmp(a: *const c_char, b: *const c_char) -> c_int;
    strncmp(a: *const c_char, b: *const c_char, count: usize) -> c_int;
    strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
    strncpy(dest: *mut c_char, src: *const c_char, count: usize) -> *mut c_char;
    strcat(dest: *mut c_char, src: *const c_char) -> *mut c_char;
    strncat(dest: *mut c_char, src: *const c_char, count: usize) -> *mut c_char;
    strcspn(text: *const c_char, reject: *const c_char) -> usize;
    strpbrk(text: *const c_char, accept: *const c_char) -> *mut c_char;
    strtok(text: *mut c_char, delimiters: *const c_char) -> *mut c_char;
    isalnum(character: c_int) -> c_int;
    isalpha(character: c_int) -> c_int;
    isdigit(character: c_int) -> c_int;
    islower(character: c_int) -> c_int;
    isspace(character: c_int) -> c_int;
    isupper(character: c_int) -> c_int;
    isxdigit(character: c_int) -> c_int;
    tolower(character: c_int) -> c_int;
    toupper(character: c_int) -> c_int;
}

mod more {
    use super::*;

    unsafe extern "C" {
        pub fn strnlen(text: *const c_char, max: usize) -> usize;
        pub fn strcasecmp(a: *const c_char, b: *const c_char) -> c_int;
        pub fn strncasecmp(a: *const c_char, b: *const c_char, count: usize) -> c_int;
        pub fn strtok_r(
            text: *mut c_char,
            delimiters: *const c_char,
            state: *mut *mut c_char,
        ) -> *mut c_char;
        pub fn qsort_r(
            base: *mut c_void,
            count: usize,
            size: usize,
            compare: extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int,
            context: *mut c_void,
        );
        pub fn getrandom(buffer: *mut c_void, length: usize, flags: u32) -> isize;
    }
}

extern "win64" fn _stricmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: the title passes NUL-terminated strings.
    unsafe { more::strcasecmp(a, b) }
}

extern "win64" fn _strnicmp(a: *const c_char, b: *const c_char, count: usize) -> c_int {
    // SAFETY: the title passes NUL-terminated strings.
    unsafe { more::strncasecmp(a, b, count) }
}

extern "win64" fn strcpy_s(dest: *mut c_char, size: usize, src: *const c_char) -> i32 {
    if dest.is_null() || size == 0 {
        return EINVAL;
    }
    if src.is_null() {
        // SAFETY: `dest` holds at least `size >= 1` bytes.
        unsafe { dest.write(0) };
        return EINVAL;
    }
    // SAFETY: the title passes a NUL-terminated `src`.
    let len = unsafe { c::strlen(src) };
    if len >= size {
        // SAFETY: `dest` holds at least `size >= 1` bytes.
        unsafe { dest.write(0) };
        return ERANGE;
    }
    // SAFETY: `len + 1 <= size` bytes fit in `dest`.
    unsafe { std::ptr::copy(src, dest, len + 1) };
    0
}

extern "win64" fn strcat_s(dest: *mut c_char, size: usize, src: *const c_char) -> i32 {
    if dest.is_null() || size == 0 {
        return EINVAL;
    }
    // SAFETY: `dest` holds at least `size` bytes.
    let used = unsafe { more::strnlen(dest, size) };
    if used == size || src.is_null() {
        // SAFETY: `dest` holds at least `size >= 1` bytes.
        unsafe { dest.write(0) };
        return EINVAL;
    }
    // SAFETY: the title passes a NUL-terminated `src`.
    let len = unsafe { c::strlen(src) };
    if used + len >= size {
        // SAFETY: `dest` holds at least `size >= 1` bytes.
        unsafe { dest.write(0) };
        return ERANGE;
    }
    // SAFETY: `used + len + 1 <= size` bytes fit in `dest`.
    unsafe { std::ptr::copy(src, dest.add(used), len + 1) };
    0
}

extern "win64" fn strncpy_s(
    dest: *mut c_char,
    size: usize,
    src: *const c_char,
    count: usize,
) -> i32 {
    if dest.is_null() || size == 0 {
        return EINVAL;
    }
    if count == 0 {
        // SAFETY: `dest` holds at least `size >= 1` bytes.
        unsafe { dest.write(0) };
        return 0;
    }
    if src.is_null() {
        // SAFETY: `dest` holds at least `size >= 1` bytes.
        unsafe { dest.write(0) };
        return EINVAL;
    }
    let truncate = count == usize::MAX;
    // SAFETY: the title passes a NUL-terminated `src`; the scan stops at the limit.
    let wanted = unsafe { more::strnlen(src, if truncate { size } else { count }) };
    let (copy, status) = if wanted < size {
        (wanted, 0)
    } else if truncate {
        (size - 1, STRUNCATE)
    } else {
        // SAFETY: `dest` holds at least `size >= 1` bytes.
        unsafe { dest.write(0) };
        return ERANGE;
    };
    // SAFETY: `copy + 1 <= size` bytes fit in `dest`.
    unsafe {
        std::ptr::copy(src, dest, copy);
        dest.add(copy).write(0);
    }
    status
}

extern "win64" fn strtok_s(
    text: *mut c_char,
    delimiters: *const c_char,
    state: *mut *mut c_char,
) -> *mut c_char {
    // SAFETY: the title passes the arguments `strtok_s` documents.
    unsafe { more::strtok_r(text, delimiters, state) }
}

extern "C" fn trampoline(a: *const c_void, b: *const c_void, compare: *mut c_void) -> c_int {
    // SAFETY: `compare` is the title's comparison function, passed through `qsort`.
    let compare: Compare = unsafe { std::mem::transmute(compare) };
    compare(a, b)
}

extern "win64" fn qsort(base: *mut c_void, count: usize, size: usize, compare: Compare) {
    // SAFETY: the title passes an array of `count` elements of `size` bytes.
    unsafe {
        more::qsort_r(
            base,
            count,
            size,
            trampoline,
            compare as *const () as *mut c_void,
        )
    }
}

extern "win64" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    count: usize,
    size: usize,
    compare: Compare,
) -> *const c_void {
    let (mut low, mut high) = (0usize, count);
    while low < high {
        let mid = low + (high - low) / 2;
        // SAFETY: `mid < count`, inside the title's array.
        let element = unsafe { base.cast::<u8>().add(mid * size) }.cast::<c_void>();
        match compare(key, element) {
            0 => return element,
            order if order < 0 => high = mid,
            _ => low = mid + 1,
        }
    }
    std::ptr::null()
}

thread_local! {
    static SEED: Cell<u32> = const { Cell::new(1) };
}

extern "win64" fn srand(seed: u32) {
    SEED.with(|cell| cell.set(seed));
}

extern "win64" fn rand() -> i32 {
    SEED.with(|cell| {
        let next = cell.get().wrapping_mul(214013).wrapping_add(2531011);
        cell.set(next);
        ((next >> 16) & 0x7fff) as i32
    })
}

extern "win64" fn rand_s(out: *mut u32) -> i32 {
    if out.is_null() {
        return EINVAL;
    }
    // SAFETY: `out` is the title's 4-byte out-parameter.
    let got = unsafe { more::getrandom(out.cast(), 4, 0) };
    if got == 4 { 0 } else { EINVAL }
}

pub fn module() -> HleModule {
    let mut exports = passthrough_exports();
    exports.extend([
        hle_export!(_stricmp),
        hle_export!(_strnicmp),
        hle_export!(strcpy_s),
        hle_export!(strcat_s),
        hle_export!(strncpy_s),
        hle_export!(strtok_s),
        hle_export!(qsort),
        hle_export!(bsearch),
        hle_export!(rand),
        hle_export!(srand),
        hle_export!(rand_s),
    ]);
    HleModule {
        name: "crt",
        dlls: &[
            "api-ms-win-crt-string-*",
            "api-ms-win-crt-heap-*",
            "api-ms-win-crt-utility-*",
        ],
        exports,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, c_char, c_void};

    use victory_loader::{ImportResolver, Resolution};
    use victory_pe::ImportSymbol;

    use super::Compare;
    use crate::{HleResolver, HostPolicy};

    fn address(symbol: &str) -> usize {
        let name = ImportSymbol::Name {
            hint: 0,
            name: symbol.into(),
        };
        let resolver = HleResolver::new(HostPolicy::none());
        match resolver.resolve("api-ms-win-crt-string-l1-1-0.dll", &name) {
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

    extern "win64" fn compare(a: *const c_void, b: *const c_void) -> i32 {
        // SAFETY: both point to `i32` elements of the arrays below.
        let (a, b) = unsafe { (a.cast::<i32>().read(), b.cast::<i32>().read()) };
        a.cmp(&b) as i32
    }

    #[test]
    fn strings_and_the_heap_behave_like_the_c_library() {
        let strlen = function!("strlen", extern "win64" fn(*const c_char) -> usize);
        assert_eq!(strlen(c"hello".as_ptr()), 5);
        let stricmp = function!(
            "_stricmp",
            extern "win64" fn(*const c_char, *const c_char) -> i32
        );
        assert_eq!(stricmp(c"ABC".as_ptr(), c"abc".as_ptr()), 0);
        let toupper = function!("toupper", extern "win64" fn(i32) -> i32);
        assert_eq!(toupper(97), 65);
        let malloc = function!("malloc", extern "win64" fn(usize) -> *mut c_void);
        let realloc = function!(
            "realloc",
            extern "win64" fn(*mut c_void, usize) -> *mut c_void
        );
        let calloc = function!("calloc", extern "win64" fn(usize, usize) -> *mut c_void);
        let free = function!("free", extern "win64" fn(*mut c_void));
        let block = malloc(16).cast::<u8>();
        assert!(!block.is_null());
        // SAFETY: the block holds 16 writable bytes.
        unsafe { block.write(7) };
        let block = realloc(block.cast(), 64).cast::<u8>();
        // SAFETY: realloc preserved the first byte.
        assert_eq!(unsafe { block.read() }, 7);
        free(block.cast());
        let zeroed = calloc(4, 4).cast::<u32>();
        // SAFETY: the block holds 16 readable bytes.
        assert_eq!(unsafe { zeroed.read() }, 0);
        free(zeroed.cast());
    }

    #[test]
    fn bounds_checked_strings_report_errors_like_the_ucrt() {
        let strcpy_s = function!(
            "strcpy_s",
            extern "win64" fn(*mut c_char, usize, *const c_char) -> i32
        );
        let strcat_s = function!(
            "strcat_s",
            extern "win64" fn(*mut c_char, usize, *const c_char) -> i32
        );
        let strncpy_s = function!(
            "strncpy_s",
            extern "win64" fn(*mut c_char, usize, *const c_char, usize) -> i32
        );
        let mut buffer = [1 as c_char; 4];
        assert_eq!(strcpy_s(buffer.as_mut_ptr(), 4, c"abc".as_ptr()), 0);
        assert_eq!(strcpy_s(buffer.as_mut_ptr(), 4, c"abcd".as_ptr()), 34);
        assert_eq!(buffer[0], 0);
        let mut small = [1 as c_char; 4];
        assert_eq!(
            strncpy_s(small.as_mut_ptr(), 4, c"abcdef".as_ptr(), usize::MAX),
            80
        );
        // SAFETY: `small` is NUL-terminated by `strncpy_s`.
        assert_eq!(unsafe { CStr::from_ptr(small.as_ptr()) }, c"abc");
        let mut joined = [0 as c_char; 8];
        assert_eq!(strcpy_s(joined.as_mut_ptr(), 8, c"foo".as_ptr()), 0);
        assert_eq!(strcat_s(joined.as_mut_ptr(), 8, c"bar".as_ptr()), 0);
        // SAFETY: `joined` is NUL-terminated by `strcat_s`.
        assert_eq!(unsafe { CStr::from_ptr(joined.as_ptr()) }, c"foobar");
        assert_eq!(strcat_s(joined.as_mut_ptr(), 8, c"xy".as_ptr()), 34);
    }

    #[test]
    fn sorting_searching_and_rand_match_the_ucrt() {
        let qsort = function!(
            "qsort",
            extern "win64" fn(*mut c_void, usize, usize, Compare)
        );
        let bsearch = function!(
            "bsearch",
            extern "win64" fn(*const c_void, *const c_void, usize, usize, Compare) -> *const c_void
        );
        let mut values = [5, 3, 9, 1, 7];
        qsort(values.as_mut_ptr().cast(), 5, 4, compare);
        assert_eq!(values, [1, 3, 5, 7, 9]);
        let key = 7;
        let found = bsearch(
            (&key as *const i32).cast(),
            values.as_ptr().cast(),
            5,
            4,
            compare,
        );
        assert_eq!(found, (&values[3] as *const i32).cast());
        let missing = 4;
        let absent = bsearch(
            (&missing as *const i32).cast(),
            values.as_ptr().cast(),
            5,
            4,
            compare,
        );
        assert!(absent.is_null());
        let srand = function!("srand", extern "win64" fn(u32));
        let rand = function!("rand", extern "win64" fn() -> i32);
        srand(1);
        assert_eq!(rand(), 41);
        assert_eq!(rand(), 18467);
    }
}
