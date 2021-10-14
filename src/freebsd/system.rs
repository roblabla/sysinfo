//
// Sysinfo
//
// Copyright (c) 2015 Guillaume Gomez
//

use crate::{
    sys::{component::Component, Disk, Networks, Process, Processor},
    LoadAvg, Pid, RefreshKind, SystemExt, User,
};

use std::collections::HashMap;
use std::mem;

use libc::{c_char, c_int, c_void, sysconf, sysctl, sysctlbyname, timeval, _SC_PAGESIZE};

use once_cell::sync::Lazy;

#[doc = include_str!("../../md_doc/system.md")]
pub struct System {
    process_list: HashMap<Pid, Process>,
    mem_total: u64,
    mem_free: u64,
    mem_available: u64,
    swap_total: u64,
    swap_free: u64,
    global_processor: Processor,
    processors: Vec<Processor>,
    components: Vec<Component>,
    disks: Vec<Disk>,
    networks: Networks,
    users: Vec<User>,
    boot_time: u64,
}

impl SystemExt for System {
    const IS_SUPPORTED: bool = true;

    fn new_with_specifics(refreshes: RefreshKind) -> System {
        let mut s = System {
            process_list: HashMap::with_capacity(200),
            mem_total: 0,
            mem_free: 0,
            mem_available: 0,
            swap_total: 0,
            swap_free: 0,
            global_processor: Processor::new(),
            processors: Vec::new(),
            components: Vec::with_capacity(2),
            disks: Vec::with_capacity(1),
            networks: Networks::new(),
            users: Vec::new(),
            boot_time: boot_time(),
        };
        s.refresh_specifics(refreshes);
        s
    }

    fn refresh_memory(&mut self) {}

    fn refresh_cpu(&mut self) {}

    fn refresh_components_list(&mut self) {}

    fn refresh_processes(&mut self) {}

    fn refresh_process(&mut self, _pid: Pid) -> bool {
        false
    }

    fn refresh_disks_list(&mut self) {}

    fn refresh_users_list(&mut self) {}

    // COMMON PART
    //
    // Need to be moved into a "common" file to avoid duplication.

    fn processes(&self) -> &HashMap<Pid, Process> {
        &self.process_list
    }

    fn process(&self, _pid: Pid) -> Option<&Process> {
        None
    }

    fn networks(&self) -> &Networks {
        &self.networks
    }

    fn networks_mut(&mut self) -> &mut Networks {
        &mut self.networks
    }

    fn global_processor_info(&self) -> &Processor {
        &self.global_processor
    }

    fn processors(&self) -> &[Processor] {
        &[]
    }

    fn physical_core_count(&self) -> Option<usize> {
        let mut physical_core_count = 0;

        if unsafe {
            get_sys_value_by_name(
                b"hw.physicalcpu\0",
                &mut mem::size_of::<u32>(),
                &mut physical_core_count as *mut usize as *mut c_void,
            )
        } {
            Some(physical_core_count)
        } else {
            None
        }
    }

    fn total_memory(&self) -> u64 {
        self.mem_total
    }

    fn free_memory(&self) -> u64 {
        self.mem_free
    }

    fn available_memory(&self) -> u64 {
        self.mem_available
    }

    fn used_memory(&self) -> u64 {
        self.mem_total - self.mem_free
    }

    fn total_swap(&self) -> u64 {
        self.swap_total
    }

    fn free_swap(&self) -> u64 {
        self.swap_free
    }

    // TODO: need to be checked
    fn used_swap(&self) -> u64 {
        self.swap_total - self.swap_free
    }

    fn components(&self) -> &[Component] {
        &[]
    }

    fn components_mut(&mut self) -> &mut [Component] {
        &mut []
    }

    fn disks(&self) -> &[Disk] {
        &[]
    }

    fn disks_mut(&mut self) -> &mut [Disk] {
        &mut []
    }

    fn uptime(&self) -> u64 {
        let csec = unsafe { libc::time(::std::ptr::null_mut()) };

        unsafe { libc::difftime(csec, self.boot_time as _) as u64 }
    }

    fn boot_time(&self) -> u64 {
        self.boot_time
    }

    fn load_average(&self) -> LoadAvg {
        let mut loads = vec![0f64; 3];
        unsafe {
            libc::getloadavg(loads.as_mut_ptr(), 3);
        }
        LoadAvg {
            one: loads[0],
            five: loads[1],
            fifteen: loads[2],
        }
    }

    fn users(&self) -> &[User] {
        &[]
    }

    fn name(&self) -> Option<String> {
        get_system_info(libc::KERN_OSTYPE, Some("Darwin"))
    }

    fn long_os_version(&self) -> Option<String> {
        None
    }

    fn host_name(&self) -> Option<String> {
        get_system_info(libc::KERN_HOSTNAME, None)
    }

    fn kernel_version(&self) -> Option<String> {
        get_system_info(libc::KERN_OSRELEASE, None)
    }

    fn os_version(&self) -> Option<String> {
        unsafe {
            // get the size for the buffer first
            let mut size = 0;
            if get_sys_value_by_name(b"kern.osproductversion\0", &mut size, std::ptr::null_mut())
                && size > 0
            {
                // now create a buffer with the size and get the real value
                let mut buf = vec![0_u8; size as usize];

                if get_sys_value_by_name(
                    b"kern.osproductversion\0",
                    &mut size,
                    buf.as_mut_ptr() as *mut c_void,
                ) {
                    if let Some(pos) = buf.iter().position(|x| *x == 0) {
                        // Shrink buffer to terminate the null bytes
                        buf.resize(pos, 0);
                    }

                    String::from_utf8(buf).ok()
                } else {
                    // getting the system value failed
                    None
                }
            } else {
                // getting the system value failed, or did not return a buffer size
                None
            }
        }
    }
}

impl Default for System {
    fn default() -> System {
        System::new()
    }
}

/// This struct is used to get system information more easily.
#[derive(Default)]
struct SystemInfo {
    hw_physical_memory: [c_int; 2],
    page_size_k: c_int,
    virtual_page_count: [c_int; 4],
    virtual_wire_count: [c_int; 4],
    virtual_active_count: [c_int; 4],
    virtual_cache_count: [c_int; 4],
    virtual_inactive_count: [c_int; 4],
    virtual_free_count: [c_int; 4],
    buf_space: [c_int; 2],
    nb_cpus: c_int,
}

#[inline]
unsafe fn init_mib(name: &[u8], mib: &mut [c_int]) {
    libc::sysctlnametomib(name.as_ptr() as _, mib.as_mut_ptr(), &mut mib.len());
}

impl SystemInfo {
    fn new() -> Self {
        let mut si = SystemInfo {
            nb_cpus: 1,
            ..Default::default()
        };
        unsafe {
            if libc::sysctlbyname(
                b"vm.stats.vm.v_page_size\0".as_ptr() as _,
                &mut si.page_size_k as *mut _ as *mut _,
                &mut mem::size_of::<c_int>(),
                std::ptr::null(),
                0,
            ) == -1
            {
                panic!("cannot get page size...");
            }
            si.page_size_k *= 1_000;
            init_mib(b"hw.physmem\0", &mut si.hw_physical_memory);
            init_mib(b"vm.stats.vm.v_page_count\0", &mut si.virtual_page_count);
            init_mib(b"vm.stats.vm.v_wire_count\0", &mut si.virtual_wire_count);
            init_mib(
                b"vm.stats.vm.v_active_count\0",
                &mut si.virtual_active_count,
            );
            init_mib(b"vm.stats.vm.v_cache_count\0", &mut si.virtual_cache_count);
            init_mib(
                b"vm.stats.vm.v_inactive_count\0",
                &mut si.virtual_inactive_count,
            );
            init_mib(b"vm.stats.vm.v_free_count\0", &mut si.virtual_free_count);
            init_mib(b"vfs.bufspace\0", &mut si.buf_space);

            let mut smp: c_int = 0;
            let mut len = mem::size_of::<c_int>();
            if libc::sysctlbyname(
                b"kern.smp.active\0".as_ptr() as _,
                &mut smp as *mut _ as *mut _,
                &mut len,
                std::ptr::null(),
                0,
            ) != 0
                || len != mem::size_of::<c_int>()
            {
                smp = 0;
            }
            if smp != 0 {
                if libc::sysctlbyname(
                    b"kern.smp.cpus\0".as_ptr() as _,
                    &mut si.nb_cpus as *mut _ as *mut _,
                    &mut mem::size_of::<c_int>(),
                    std::ptr::null(),
                    0,
                ) != 0
                {
                    si.nb_cpus = 1;
                }
            }
        }

        si
    }

    // fn get_total_physical_memory(&self) -> u64 {
    //     let mut total_memory: u64 = 0;
    //     unsafe {
    //         get_sys_value(&self.hw_physical_memory, &mut total_memory);
    //     }
    //     total_memory
    // }

    fn get_used_memory(&self) -> u64 {
        let mut mem_active: u64 = 0;
        let mut mem_wire: u64 = 0;

        unsafe {
            get_sys_value(&self.virtual_active_count, &mut mem_active);
            get_sys_value(&self.virtual_wire_count, &mut mem_wire);
        }

        (mem_active * self.page_size_k as u64) + (mem_wire * self.page_size_k as u64)
    }

    fn get_free_memory(&self) -> u64 {
        let mut buffers_mem: u64 = 0;
        let mut inactive_mem: u64 = 0;
        let mut cached_mem: u64 = 0;
        let mut free_mem: u64 = 0;

        unsafe {
            get_sys_value(&self.buf_space, &mut buffers_mem);
            get_sys_value(&self.virtual_inactive_count, &mut inactive_mem);
            get_sys_value(&self.virtual_cache_count, &mut cached_mem);
            get_sys_value(&self.virtual_free_count, &mut free_mem);
        }
        // For whatever reason, buffers_mem is already the right value...
        buffers_mem
            + (inactive_mem * self.page_size_k as u64)
            + (cached_mem * self.page_size_k as u64)
            + (free_mem * self.page_size_k as u64)
    }
}

static SYSTEM_INFO: Lazy<SystemInfo> = Lazy::new(SystemInfo::new);

fn boot_time() -> u64 {
    let mut boot_time = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of::<timeval>();
    let mut mib: [c_int; 2] = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    if unsafe {
        sysctl(
            mib.as_mut_ptr(),
            2,
            &mut boot_time as *mut timeval as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } < 0
    {
        0
    } else {
        boot_time.tv_sec as _
    }
}

pub(crate) unsafe fn get_sys_value<T>(mib: &[c_int], value: &mut T) -> bool {
    let mut len = mem::size_of::<T>();
    sysctl(
        mib.as_ptr(),
        mib.len() as _,
        value as *mut _ as *mut _,
        &mut len as *mut _,
        std::ptr::null_mut(),
        0,
    ) == 0
}

unsafe fn get_sys_value_by_name(name: &[u8], len: &mut usize, value: *mut c_void) -> bool {
    sysctlbyname(
        name.as_ptr() as *const c_char,
        value,
        len,
        std::ptr::null_mut(),
        0,
    ) == 0
}

fn get_system_info(value: c_int, default: Option<&str>) -> Option<String> {
    let mut mib: [c_int; 2] = [libc::CTL_KERN, value];
    let mut size = 0;

    // Call first to get size
    unsafe {
        sysctl(
            mib.as_mut_ptr(),
            2,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    // exit early if we did not update the size
    if size == 0 {
        default.map(|s| s.to_owned())
    } else {
        // set the buffer to the correct size
        let mut buf = vec![0_u8; size as usize];

        if unsafe {
            sysctl(
                mib.as_mut_ptr(),
                2,
                buf.as_mut_ptr() as _,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } == -1
        {
            // If command fails return default
            default.map(|s| s.to_owned())
        } else {
            if let Some(pos) = buf.iter().position(|x| *x == 0) {
                // Shrink buffer to terminate the null bytes
                buf.resize(pos, 0);
            }

            String::from_utf8(buf).ok()
        }
    }
}
