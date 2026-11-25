#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, c_int};

use crate::{HleExport, HleModule, hle_export};

const ERANGE: i32 = 34;

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
    atoll(text: *const c_char) -> i64;
    atof(text: *const c_char) -> f64;
    strtod(text: *const c_char, end: *mut *mut c_char) -> f64;
    strtof(text: *const c_char, end: *mut *mut c_char) -> f32;
    strtoll(text: *const c_char, end: *mut *mut c_char, base: c_int) -> i64;
    strtoull(text: *const c_char, end: *mut *mut c_char, base: c_int) -> u64;
}

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

fn set_range_error() {
    // SAFETY: errno is thread-local and always writable.
    unsafe { __errno_location().write(ERANGE) };
}

extern "win64" fn strtol(text: *const c_char, end: *mut *mut c_char, base: c_int) -> i32 {
    // SAFETY: the title passes the arguments `strtol` documents.
    let value = unsafe { c::strtoll(text, end, base) };
    match i32::try_from(value) {
        Ok(value) => value,
        Err(_) => {
            set_range_error();
            if value < 0 { i32::MIN } else { i32::MAX }
        }
    }
}

extern "win64" fn strtoul(text: *const c_char, end: *mut *mut c_char, base: c_int) -> u32 {
    // SAFETY: the title passes the arguments `strtoul` documents.
    let value = unsafe { c::strtoull(text, end, base) };
    match u32::try_from(value) {
        Ok(value) => value,
        Err(_) if value >= u64::MAX - u64::from(u32::MAX) => value as u32,
        Err(_) => {
            set_range_error();
            u32::MAX
        }
    }
}

extern "win64" fn atol(text: *const c_char) -> i32 {
    strtol(text, std::ptr::null_mut(), 10)
}

extern "win64" fn atoi(text: *const c_char) -> i32 {
    strtol(text, std::ptr::null_mut(), 10)
}

extern "win64" fn _strtoi64(text: *const c_char, end: *mut *mut c_char, base: c_int) -> i64 {
    // SAFETY: the title passes the arguments `_strtoi64` documents.
    unsafe { c::strtoll(text, end, base) }
}

extern "win64" fn _strtoui64(text: *const c_char, end: *mut *mut c_char, base: c_int) -> u64 {
    // SAFETY: the title passes the arguments `_strtoui64` documents.
    unsafe { c::strtoull(text, end, base) }
}

extern "win64" fn _itoa(value: i32, buffer: *mut c_char, radix: c_int) -> *mut c_char {
    let radix = if (2..=36).contains(&radix) { radix as u32 } else { 10 };
    let negative = value < 0 && radix == 10;
    let mut rest = if negative {
        value.unsigned_abs()
    } else {
        value as u32
    };
    let mut digits = [0u8; 34];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = char::from_digit(rest % radix, radix).unwrap_or('0') as u8;
        rest /= radix;
        if rest == 0 {
            break;
        }
    }
    let text = &digits[at..];
    // SAFETY: the title's buffer holds the digits, a sign and a NUL, as `_itoa` requires.
    unsafe {
        let mut out = buffer;
        if negative {
            out.write(b'-' as c_char);
            out = out.add(1);
        }
        std::ptr::copy_nonoverlapping(text.as_ptr().cast::<c_char>(), out, text.len());
        out.add(text.len()).write(0);
    }
    buffer
}

pub fn module() -> HleModule {
    let mut exports = passthrough_exports();
    exports.extend([
        hle_export!(strtol),
        hle_export!(strtoul),
        hle_export!(atol),
        hle_export!(atoi),
        hle_export!(_strtoi64),
        hle_export!(_strtoui64),
        hle_export!(_itoa),
    ]);
    HleModule {
        name: "crt-convert",
        dlls: &["api-ms-win-crt-convert-*"],
        exports,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, c_char};

    use victory_loader::{ImportResolver, Resolution};
    use victory_pe::ImportSymbol;

    use crate::{HleResolver, HostPolicy};

    fn address(symbol: &str) -> usize {
        let name = ImportSymbol::Name {
            hint: 0,
            name: symbol.into(),
        };
        let resolver = HleResolver::new(HostPolicy::none());
        match resolver.resolve("api-ms-win-crt-convert-l1-1-0.dll", &name) {
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

    #[test]
    fn long_is_thirty_two_bits_like_on_windows() {
        let strtol = function!(
            "strtol",
            extern "win64" fn(*const c_char, *mut *mut c_char, i32) -> i32
        );
        let strtoul = function!(
            "strtoul",
            extern "win64" fn(*const c_char, *mut *mut c_char, i32) -> u32
        );
        let text = c"123abc";
        let mut end = std::ptr::null_mut();
        assert_eq!(strtol(text.as_ptr(), &mut end, 10), 123);
        // SAFETY: `end` points inside `text`.
        assert_eq!(unsafe { CStr::from_ptr(end) }, c"abc");
        assert_eq!(strtol(c"99999999999".as_ptr(), std::ptr::null_mut(), 10), i32::MAX);
        assert_eq!(strtol(c"-99999999999".as_ptr(), std::ptr::null_mut(), 10), i32::MIN);
        assert_eq!(strtol(c"ff".as_ptr(), std::ptr::null_mut(), 16), 255);
        assert_eq!(strtoul(c"-1".as_ptr(), std::ptr::null_mut(), 10), u32::MAX);
        assert_eq!(strtoul(c"4294967296".as_ptr(), std::ptr::null_mut(), 10), u32::MAX);
        assert_eq!(strtoul(c"4294967295".as_ptr(), std::ptr::null_mut(), 10), u32::MAX);
    }

    #[test]
    fn atoi_floats_and_itoa_convert_text() {
        let atoi = function!("atoi", extern "win64" fn(*const c_char) -> i32);
        assert_eq!(atoi(c"  -42x".as_ptr()), -42);
        let strtod = function!(
            "strtod",
            extern "win64" fn(*const c_char, *mut *mut c_char) -> f64
        );
        let mut end = std::ptr::null_mut();
        assert_eq!(strtod(c"1.5abc".as_ptr(), &mut end), 1.5);
        // SAFETY: `end` points inside the literal.
        assert_eq!(unsafe { CStr::from_ptr(end) }, c"abc");
        let itoa = function!(
            "_itoa",
            extern "win64" fn(i32, *mut c_char, i32) -> *mut c_char
        );
        let mut buffer = [0 as c_char; 40];
        itoa(-12, buffer.as_mut_ptr(), 10);
        // SAFETY: `_itoa` NUL-terminates the buffer.
        assert_eq!(unsafe { CStr::from_ptr(buffer.as_ptr()) }, c"-12");
        itoa(255, buffer.as_mut_ptr(), 16);
        // SAFETY: `_itoa` NUL-terminates the buffer.
        assert_eq!(unsafe { CStr::from_ptr(buffer.as_ptr()) }, c"ff");
        itoa(-255, buffer.as_mut_ptr(), 16);
        // SAFETY: `_itoa` NUL-terminates the buffer.
        assert_eq!(unsafe { CStr::from_ptr(buffer.as_ptr()) }, c"ffffff01");
    }
}
