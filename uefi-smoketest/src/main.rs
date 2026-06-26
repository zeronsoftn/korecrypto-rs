// x86_64-unknown-uefi 타깃에서 korecrypto-sys(FIPS + picolibc) 를 실제 UEFI 환경
// (QEMU + OVMF)에서 부팅·실행해 FIPS 자가시험을 검증하는 스모크 테스트.
//
//  - 시리얼(COM1, 16550)로 결과를 출력한다 → QEMU `-serial stdio` 로 호스트에서 캡처.
//  - FIPS_mode / BORINGSSL_integrity_test / BORINGSSL_self_test_all 을 실행하고
//    반환값과 최종 "RESULT: PASS|FAIL" 한 줄을 출력한다.
//  - 끝나면 ACPI(S5)로 QEMU 를 종료한다.
//
// 빌드·실행은 run-qemu.sh 또는 README.md 참고.
#![no_std]
#![no_main]

extern crate alloc;
extern crate picolibc;

use core::arch::asm;
use core::ffi::{c_int, c_void};
use uefi::prelude::*;

use log;

#[allow(improper_ctypes)]

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn outw(port: u16, val: u16) {
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
}

#[cfg(target_arch = "x86_64")]
/// QEMU(q35/ICH9) ACPI 로 전원 종료(S5). 실패 시 무한 대기(호스트 timeout 이 종료).
unsafe fn poweroff() -> ! {
    outw(0x604, 0x2000); // PM1a_CNT: SLP_EN | SLP_TYP(S5)
    loop {
        core::hint::spin_loop();
    }
}

const PSCI_SYSTEM_OFF: usize = 0x8400_0008;

#[cfg(target_arch = "aarch64")]
unsafe fn poweroff() -> ! {
    unsafe {
        asm!(
            "hvc #0",
            in("x0") PSCI_SYSTEM_OFF,
            options(noreturn)
        );
    }
}

#[no_mangle]
extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> isize {
    // boringssl/libc 의 stdout(1)/stderr(2) 출력을 로거(→시리얼)로 전달한다.
    // 자가시험 실패/abort 사유 등 진단 메시지를 호스트에서 볼 수 있게 한다.
    if (fd == 1 || fd == 2) && !buf.is_null() && count > 0 {
        let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
        match core::str::from_utf8(bytes) {
            Ok(s) => log::info!("[bssl] {}", s.trim_end_matches(['\r', '\n'])),
            Err(_) => log::info!("[bssl] <{count} bytes>"),
        }
    }
    count as isize
}

#[no_mangle]
extern "C" fn read(_fd: c_int, _buf: *mut c_void, _count: usize) -> isize {
    0
}

#[no_mangle]
extern "C" fn lseek(_fd: c_int, _off: i64, _whence: c_int) -> i64 {
    -1
}

#[no_mangle]
extern "C" fn close(_fd: c_int) -> c_int {
    0
}

#[no_mangle]
extern "C" fn _exit(_code: c_int) -> ! {
    unsafe { poweroff() }
}

// mingw64 어셈블리의 SE 핸들러(se_handler)들은 `__imp_RtlVirtualUnwind` 를
// 간접 호출한다. UEFI 는 예외(-fno-exceptions)를 사용하지 않으므로 실제로 호출되지
// 않는다. 링크 오류 해소를 위해 null 포인터 IAT 엔트리를 제공한다.
core::arch::global_asm!(
    ".globl __imp_RtlVirtualUnwind",
    "__imp_RtlVirtualUnwind:",
    "    .quad 0",
);

// MS x64 ABI(=UEFI)에서 clang 은 스택 프레임이 한 페이지(4KB)를 넘으면 스택 프로빙
// 호출(__chkstk)을 삽입한다. UEFI 부팅 스택은 전부 커밋되어 있어 프로빙이 불필요
// 하므로, RAX(요청 크기)를 보존하고 즉시 반환하는 no-op 스텁으로 충족한다.
core::arch::global_asm!(
    ".globl __chkstk",
    "__chkstk:",
    "    ret",
    ".globl ___chkstk_ms",
    "___chkstk_ms:",
    "    ret",
);


const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR0_NE: u64 = 1 << 5;

const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

#[cfg(target_arch = "x86_64")]
#[inline]
fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading CR0 is a privileged but side-effect-free register read;
    // the loader runs at ring 0.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: as read_cr0, for CR4.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn write_cr0(v: u64) {
    // SAFETY: ring-0 control-register write. `nomem` is intentionally omitted:
    // toggling CR0 affects how the CPU executes, so the compiler must not move
    // memory accesses across it.
    unsafe {
        core::arch::asm!("mov cr0, {}", in(reg) v, options(nostack, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn write_cr4(v: u64) {
    // SAFETY: as write_cr0, for CR4.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) v, options(nostack, preserves_flags));
    }
}

#[inline]
fn bit(v: u64, b: u64) -> u32 {
    ((v & b) != 0) as u32
}

#[cfg(target_arch = "x86_64")]
pub fn report_and_enable_xmm() {
    let cr0 = read_cr0();
    let cr4 = read_cr4();

    log::info!(
        "cpu: current CR0.MP[1]={} CR0.EM[2]={} CR0.TS[3]={} CR0.NE[5]={} \
         CR4.OSFXSR[9]={} CR4.OSXMMEXCPT[10]={}",
        bit(cr0, CR0_MP),
        bit(cr0, CR0_EM),
        bit(cr0, CR0_TS),
        bit(cr0, CR0_NE),
        bit(cr4, CR4_OSFXSR),
        bit(cr4, CR4_OSXMMEXCPT),
    );

    /*
     * Enable x87 FPU / SSE / XMM.
     *
     * CR0.MP = 1
     * CR0.EM = 0
     * CR0.TS = 0
     * CR0.NE = 1
     *
     * CR4.OSFXSR     = 1
     * CR4.OSXMMEXCPT = 1
     */
    let new_cr0 = (cr0 | CR0_MP | CR0_NE) & !(CR0_EM | CR0_TS);
    let new_cr4 = cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT;

    if new_cr0 != cr0 {
        write_cr0(new_cr0);
    }

    if new_cr4 != cr4 {
        write_cr4(new_cr4);
    }

    unsafe {
        core::arch::asm!(
            "fninit",
            options(nostack, preserves_flags)
        );

        let mxcsr: u32 = 0x1f80;
        core::arch::asm!(
            "ldmxcsr [{}]",
            in(reg) &mxcsr,
            options(nostack, preserves_flags)
        );
    }

    log::info!(
        "cpu: enabled XMM CR0 {:#x}->{:#x} CR4 {:#x}->{:#x} \
         (MP=1 EM=0 TS=0 NE=1 OSFXSR=1 OSXMMEXCPT=1 MXCSR=0x1f80)",
        cr0,
        new_cr0,
        cr4,
        new_cr4,
    );
}

#[cfg(not(target_arch = "x86_64"))]
pub fn report_and_enable_xmm() {}

#[entry]
fn main() -> Status {
    let _ = uefi::helpers::init();

    report_and_enable_xmm();

    unsafe {
        log::info!("=== korecrypto UEFI FIPS smoketest ===");

        // FIPS 엔트로피: UEFI 에서 BoringSSL 의 CRYPTO_sysrand 는 EFI_RNG_PROTOCOL 을
        // 통해 난수를 얻으며, 그러려면 Boot Services 포인터를 CRYPTO_uefi_init 으로
        // 먼저 전달해야 한다. 호출하지 않으면 첫 RNG 사용 시 abort 한다(RSA 자가시험 등).
        let bs = uefi::table::system_table_raw()
            .expect("UEFI system table unavailable")
            .as_ref()
            .boot_services;
        korecrypto_sys::CRYPTO_uefi_init(bs.cast());
        log::info!("CRYPTO_uefi_init(boot_services={bs:p}) done");

        korecrypto_sys::CRYPTO_library_init();

        // FIPS 자가시험 3종 실행(각 1=성공).
        let fips_mode = korecrypto_sys::FIPS_mode();
        log::info!("FIPS_mode={fips_mode}");

        let integrity = korecrypto_sys::BORINGSSL_integrity_test();
        log::info!("BORINGSSL_integrity_test={integrity}");

        let self_test = korecrypto_sys::BORINGSSL_self_test_all();

        log::info!("BORINGSSL_self_test_all={self_test}");

        let ok = fips_mode == 1 && integrity == 1 && self_test == 1;

        // run-qemu.sh 가 grep 하는 결과 표지.
        log::info!("RESULT: {}", if ok { "PASS" } else { "FAIL" });

        poweroff();
    }
}
