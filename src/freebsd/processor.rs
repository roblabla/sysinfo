//
// Sysinfo
//
// Copyright (c) 2015 Guillaume Gomez
//

use crate::ProcessorExt;

use libc::c_char;

/// Dummy struct that represents a processor.
pub struct Processor {}

impl Processor {
    pub(crate) fn new() -> Processor {
        Processor {}
    }
}

impl ProcessorExt for Processor {
    fn cpu_usage(&self) -> f32 {
        0.0
    }

    fn name(&self) -> &str {
        ""
    }

    fn frequency(&self) -> u64 {
        0
    }

    fn vendor_id(&self) -> &str {
        ""
    }

    fn brand(&self) -> &str {
        ""
    }
}

fn get_sysctl_str(s: &[u8]) -> String {
    let mut len = 0;

    unsafe {
        libc::sysctlbyname(
            s.as_ptr() as *const c_char,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        );
    }
    if len < 1 {
        return String::new();
    }
    let mut buf = Vec::with_capacity(len);
    unsafe {
        libc::sysctlbyname(
            s.as_ptr() as *const c_char,
            buf.as_mut_ptr() as _,
            &mut len,
            std::ptr::null_mut(),
            0,
        );
    }
    if len > 0 {
        unsafe {
            buf.set_len(len);
        }
        while buf.last() == Some(&b'\0') {
            buf.pop();
        }
        String::from_utf8(buf).unwrap_or_else(|_| String::new())
    } else {
        String::new()
    }
}

pub fn get_vendor_id_and_brand() -> (String, String) {
    let mut vendor = get_sysctl_str(b"machdep.cpu.vendor\0");

    (vendor, get_sysctl_str(b"machdep.cpu.brand_string\0"))
}
