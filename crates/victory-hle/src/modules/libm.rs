#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_long, c_void};
use std::num::FpCategory;

use crate::{HleExport, HleModule, hle_export};

macro_rules! passthrough {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        mod c {
            #[link(name = "m")]
            unsafe extern "C" {
                $(pub safe fn $name($($arg: $ty),*) -> $ret;)*
            }
        }

        $(
            extern "win64" fn $name($($arg: $ty),*) -> $ret {
                c::$name($($arg),*)
            }
        )*

        fn passthrough_exports() -> Vec<HleExport> {
            vec![$(hle_export!($name)),*]
        }
    };
}

passthrough! {
    acos(x: f64) -> f64;
    asin(x: f64) -> f64;
    atan(x: f64) -> f64;
    cos(x: f64) -> f64;
    sin(x: f64) -> f64;
    tan(x: f64) -> f64;
    exp(x: f64) -> f64;
    exp2(x: f64) -> f64;
    log(x: f64) -> f64;
    log2(x: f64) -> f64;
    atan2(y: f64, x: f64) -> f64;
    pow(x: f64, y: f64) -> f64;
    fmod(x: f64, y: f64) -> f64;
    ldexp(x: f64, exponent: i32) -> f64;
    acosf(x: f32) -> f32;
    asinf(x: f32) -> f32;
    atanf(x: f32) -> f32;
    cosf(x: f32) -> f32;
    sinf(x: f32) -> f32;
    tanf(x: f32) -> f32;
    sinhf(x: f32) -> f32;
    expf(x: f32) -> f32;
    exp2f(x: f32) -> f32;
    logf(x: f32) -> f32;
    log10f(x: f32) -> f32;
    log2f(x: f32) -> f32;
    cbrtf(x: f32) -> f32;
    ceilf(x: f32) -> f32;
    erff(x: f32) -> f32;
    atan2f(y: f32, x: f32) -> f32;
    powf(x: f32, y: f32) -> f32;
    fmodf(x: f32, y: f32) -> f32;
    remainderf(x: f32, y: f32) -> f32;
    nextafterf(x: f32, y: f32) -> f32;
}

mod ext {
    use std::ffi::c_long;

    #[link(name = "m")]
    unsafe extern "C" {
        pub safe fn lroundf(x: f32) -> c_long;
        pub fn frexp(x: f64, exponent: *mut i32) -> f64;
        pub fn modf(x: f64, integral: *mut f64) -> f64;
        pub fn modff(x: f32, integral: *mut f32) -> f32;
    }
}

extern "win64" fn lroundf(x: f32) -> i32 {
    let rounded: c_long = ext::lroundf(x);
    rounded as i32
}

extern "win64" fn frexp(x: f64, exponent: *mut i32) -> f64 {
    // SAFETY: the pointer is the title's own out-parameter, as in the C library.
    unsafe { ext::frexp(x, exponent) }
}

extern "win64" fn modf(x: f64, integral: *mut f64) -> f64 {
    // SAFETY: the pointer is the title's own out-parameter, as in the C library.
    unsafe { ext::modf(x, integral) }
}

extern "win64" fn modff(x: f32, integral: *mut f32) -> f32 {
    // SAFETY: the pointer is the title's own out-parameter, as in the C library.
    unsafe { ext::modff(x, integral) }
}

extern "win64" fn nexttowardf(x: f32, y: f64) -> f32 {
    if x.is_nan() || y.is_nan() {
        return f32::NAN;
    }
    let from = f64::from(x);
    if from == y {
        return y as f32;
    }
    c::nextafterf(
        x,
        if from < y {
            f32::INFINITY
        } else {
            f32::NEG_INFINITY
        },
    )
}

fn category(class: FpCategory) -> i16 {
    match class {
        FpCategory::Nan => 2,
        FpCategory::Infinite => 1,
        FpCategory::Zero => 0,
        FpCategory::Subnormal => -2,
        FpCategory::Normal => -1,
    }
}

extern "win64" fn _dtest(x: *const f64) -> i16 {
    // SAFETY: the title passes a valid pointer, as the C library requires.
    category(unsafe { x.read() }.classify())
}

extern "win64" fn _fdtest(x: *const f32) -> i16 {
    // SAFETY: the title passes a valid pointer, as the C library requires.
    category(unsafe { x.read() }.classify())
}

extern "win64" fn _fdsign(x: f32) -> i32 {
    if x.is_sign_negative() { 0x8000 } else { 0 }
}

extern "win64" fn _isnan(x: f64) -> i32 {
    i32::from(x.is_nan())
}

extern "win64" fn __setusermatherr(_handler: *const c_void) {}

pub fn module() -> HleModule {
    let mut exports = passthrough_exports();
    exports.extend([
        hle_export!(lroundf),
        hle_export!(frexp),
        hle_export!(modf),
        hle_export!(modff),
        hle_export!(nexttowardf),
        hle_export!(_dtest),
        hle_export!(_fdtest),
        hle_export!(_fdsign),
        hle_export!(_isnan),
        hle_export!(__setusermatherr),
    ]);
    HleModule {
        name: "libm",
        dlls: &["api-ms-win-crt-math-*"],
        exports,
    }
}

#[cfg(test)]
mod tests {
    use victory_loader::{ImportResolver, Resolution};
    use victory_pe::ImportSymbol;

    use crate::{HleResolver, HostPolicy};

    fn address(symbol: &str) -> usize {
        let name = ImportSymbol::Name {
            hint: 0,
            name: symbol.into(),
        };
        let resolver = HleResolver::new(HostPolicy::none());
        match resolver.resolve("api-ms-win-crt-math-l1-1-0.dll", &name) {
            Resolution::Found { address, .. } => address,
            Resolution::Missing => panic!("{symbol} is not resolved"),
        }
    }

    #[test]
    fn resolved_functions_compute_through_the_windows_abi() {
        // SAFETY: each signature below is the one the function was declared with.
        unsafe {
            let pow: extern "win64" fn(f64, f64) -> f64 = std::mem::transmute(address("pow"));
            assert_eq!(pow(2.0, 10.0), 1024.0);
            let sinf: extern "win64" fn(f32) -> f32 = std::mem::transmute(address("sinf"));
            assert_eq!(sinf(0.0), 0.0);
            let lroundf: extern "win64" fn(f32) -> i32 = std::mem::transmute(address("lroundf"));
            assert_eq!(lroundf(2.5), 3);
            assert_eq!(lroundf(-2.5), -3);
            let frexp: extern "win64" fn(f64, *mut i32) -> f64 =
                std::mem::transmute(address("frexp"));
            let mut exponent = 0;
            assert_eq!(frexp(8.0, &mut exponent), 0.5);
            assert_eq!(exponent, 4);
            let modf: extern "win64" fn(f64, *mut f64) -> f64 = std::mem::transmute(address("modf"));
            let mut integral = 0.0;
            assert_eq!(modf(3.25, &mut integral), 0.25);
            assert_eq!(integral, 3.0);
            let toward: extern "win64" fn(f32, f64) -> f32 =
                std::mem::transmute(address("nexttowardf"));
            assert_eq!(toward(1.0, 2.0), f32::from_bits(1.0f32.to_bits() + 1));
            assert_eq!(toward(1.0, 1.0), 1.0);
            let dtest: extern "win64" fn(*const f64) -> i16 = std::mem::transmute(address("_dtest"));
            assert_eq!(dtest(&f64::NAN), 2);
            assert_eq!(dtest(&0.0), 0);
            let fdsign: extern "win64" fn(f32) -> i32 = std::mem::transmute(address("_fdsign"));
            assert_eq!(fdsign(-1.0), 0x8000);
            assert_eq!(fdsign(1.0), 0);
        }
    }
}
