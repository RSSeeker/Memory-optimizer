//! 内存整理独立工具
//!
//! Windows 一键内存整理：开启所需特权后，调用 ntdll 的 NtSetSystemInformation
//! 清理系统文件缓存、修剪待机/已修改内存列表并触发内存合并，
//! 随后报告释放了多少内存。
//!
//! 用法:
//!   memory-optimizer.exe            一键整理（非管理员时自动请求 UAC 提权）
//!   memory-optimizer.exe --status   只读查看当前内存与权限状态
//!   memory-optimizer.exe --memory-optimize  提权辅助模式（内部使用）

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_helper = args.iter().any(|arg| arg == "--memory-optimize");
    let is_status = args.iter().any(|arg| arg == "--status");

    #[cfg(target_os = "windows")]
    {
        if is_helper {
            // 由父进程通过 UAC 启动的提权辅助模式，结果以退出码返回
            match windows::optimize_windows_memory() {
                Ok(()) => {
                    println!("内存整理完成。");
                    exit(0);
                }
                Err(error) => {
                    eprintln!("内存整理失败: {error}");
                    exit(1);
                }
            }
        } else if is_status {
            windows::print_status();
            windows::pause_if_double_clicked();
        } else {
            let before = windows::available_memory_bytes();
            println!("== 内存整理工具 ==");
            println!("优化前可用内存: {}", windows::format_bytes(before));

            match windows::optimize_windows_memory() {
                Ok(()) => {}
                Err(_) => {
                    println!("当前没有管理员权限，正在请求管理员权限执行…");
                    if let Err(error) = windows::run_elevated_helper() {
                        eprintln!("请求管理员权限失败: {error}");
                        windows::pause_if_double_clicked();
                        exit(1);
                    }
                }
            }

            let after = windows::available_memory_bytes();
            let reclaimed = after.saturating_sub(before);
            println!("优化后可用内存: {}", windows::format_bytes(after));
            println!("释放内存: {}", windows::format_bytes(reclaimed));
            windows::pause_if_double_clicked();
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (is_helper, is_status);
        eprintln!("该工具仅支持 Windows。");
        exit(1);
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::process::Command;
    use std::ptr::null_mut;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Luid {
        low_part: u32,
        high_part: i32,
    }

    #[repr(C)]
    struct LuidAndAttributes {
        luid: Luid,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenPrivileges {
        privilege_count: u32,
        privileges: [LuidAndAttributes; 1],
    }

    #[repr(C)]
    #[derive(Default)]
    struct SystemFileCacheInformation {
        current_size: usize,
        peak_size: usize,
        page_fault_count: u32,
        minimum_working_set: usize,
        maximum_working_set: usize,
        current_size_including_transition_in_pages: usize,
        peak_size_including_transition_in_pages: usize,
        transition_repurpose_count: u32,
        flags: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct MemoryCombineInformationEx {
        handle: isize,
        pages_combined: usize,
        flags: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct MemoryStatusEx {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_extended_virtual: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(object: *mut c_void) -> i32;
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
        fn GetConsoleProcessList(
            process_list: *mut u32,
            process_count: u32,
        ) -> u32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: *mut c_void,
            desired_access: u32,
            token_handle: *mut *mut c_void,
        ) -> i32;
        fn LookupPrivilegeValueW(
            system_name: *const u16,
            name: *const u16,
            luid: *mut Luid,
        ) -> i32;
        fn AdjustTokenPrivileges(
            token_handle: *mut c_void,
            disable_all_privileges: i32,
            new_state: *const TokenPrivileges,
            buffer_length: u32,
            previous_state: *mut TokenPrivileges,
            return_length: *mut u32,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtSetSystemInformation(
            system_information_class: u32,
            system_information: *mut c_void,
            system_information_length: u32,
        ) -> i32;
    }

    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x20;
    const TOKEN_QUERY: u32 = 0x8;
    const SE_PRIVILEGE_ENABLED: u32 = 0x2;
    const TOKEN_ELEVATION: u32 = 20;

    pub fn available_memory_bytes() -> u64 {
        let mut status = MemoryStatusEx {
            dw_length: size_of::<MemoryStatusEx>() as u32,
            ..Default::default()
        };
        unsafe {
            GlobalMemoryStatusEx(&mut status);
        }
        status.ull_avail_phys
    }

    pub fn format_bytes(bytes: u64) -> String {
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        const MIB: f64 = 1024.0 * 1024.0;
        if (bytes as f64) >= GIB {
            format!("{:.2} GB", bytes as f64 / GIB)
        } else {
            format!("{:.0} MB", bytes as f64 / MIB)
        }
    }

    pub fn print_status() {
        let mut status = MemoryStatusEx {
            dw_length: size_of::<MemoryStatusEx>() as u32,
            ..Default::default()
        };
        unsafe {
            GlobalMemoryStatusEx(&mut status);
        }
        println!("== 内存整理工具 ==");
        println!("总内存: {}", format_bytes(status.ull_total_phys));
        println!("可用内存: {}", format_bytes(status.ull_avail_phys));
        println!("管理员权限: {}", if is_elevated() { "是" } else { "否" });
        println!(
            "提示: 直接运行将清理系统文件缓存与待机列表，非管理员时会弹出 UAC 请求。"
        );
    }

    fn is_elevated() -> bool {
        let process = unsafe { GetCurrentProcess() };
        let mut token = null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return false;
        }
        let mut elevation = TokenElevation::default();
        let mut returned = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TOKEN_ELEVATION,
                (&mut elevation as *mut TokenElevation).cast(),
                size_of::<TokenElevation>() as u32,
                &mut returned,
            )
        } != 0;
        unsafe {
            CloseHandle(token);
        }
        ok && elevation.token_is_elevated != 0
    }

    /// 执行内存整理：清理系统文件缓存、修剪待机/已修改内存列表并触发内存合并。
    pub fn optimize_windows_memory() -> Result<(), String> {
        let process = unsafe { GetCurrentProcess() };
        let mut token = null_mut();
        if unsafe {
            OpenProcessToken(
                process,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }

        let result = (|| {
            for privilege in [
                "SeProfileSingleProcessPrivilege",
                "SeIncreaseQuotaPrivilege",
            ] {
                let mut wide = privilege.encode_utf16().collect::<Vec<_>>();
                wide.push(0);
                let mut luid = Luid::default();
                if unsafe {
                    LookupPrivilegeValueW(null_mut(), wide.as_ptr(), &mut luid)
                } == 0
                {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                let privileges = TokenPrivileges {
                    privilege_count: 1,
                    privileges: [LuidAndAttributes {
                        luid,
                        attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };
                if unsafe {
                    AdjustTokenPrivileges(
                        token,
                        0,
                        &privileges,
                        0,
                        null_mut(),
                        null_mut(),
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().to_string());
                }
            }

            let mut statuses = Vec::with_capacity(7);
            let mut info = 2_i32;
            statuses.push(unsafe {
                NtSetSystemInformation(
                    80,
                    (&mut info as *mut i32).cast(),
                    size_of::<i32>() as u32,
                )
            });
            let mut cache = SystemFileCacheInformation {
                minimum_working_set: usize::MAX,
                maximum_working_set: usize::MAX,
                ..Default::default()
            };
            statuses.push(unsafe {
                NtSetSystemInformation(
                    81,
                    (&mut cache as *mut SystemFileCacheInformation).cast(),
                    size_of::<SystemFileCacheInformation>() as u32,
                )
            });
            for value in [3_i32, 4, 5] {
                info = value;
                statuses.push(unsafe {
                    NtSetSystemInformation(
                        80,
                        (&mut info as *mut i32).cast(),
                        size_of::<i32>() as u32,
                    )
                });
            }
            statuses
                .push(unsafe { NtSetSystemInformation(155, null_mut(), 0) });
            let mut combine = MemoryCombineInformationEx::default();
            statuses.push(unsafe {
                NtSetSystemInformation(
                    130,
                    (&mut combine as *mut MemoryCombineInformationEx).cast(),
                    size_of::<MemoryCombineInformationEx>() as u32,
                )
            });

            if statuses[0] < 0 && statuses[1] < 0 {
                return Err("需要管理员权限".to_string());
            }
            Ok(())
        })();

        unsafe {
            CloseHandle(token);
        }
        result
    }

    /// 以管理员权限重新启动自身并执行 --memory-optimize。
    pub fn run_elevated_helper() -> Result<(), String> {
        let executable = std::env::current_exe()
            .map_err(|error| format!("无法定位当前程序: {error}"))?;
        let escaped = executable.to_string_lossy().replace('\'', "''");
        let command = format!(
            "$process = Start-Process -FilePath '{escaped}' -ArgumentList '--memory-optimize' -Verb RunAs -Wait -PassThru; exit $process.ExitCode"
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .status()
            .map_err(|error| format!("无法启动提权进程: {error}"))?;

        if status.success() {
            Ok(())
        } else {
            Err("管理员权限被拒绝".to_string())
        }
    }

    /// 双击运行（控制台仅有本进程）时，结束后暂停等待回车，方便查看结果。
    pub fn pause_if_double_clicked() {
        let mut list = [0u32; 2];
        let count = unsafe {
            GetConsoleProcessList(list.as_mut_ptr(), list.len() as u32)
        };
        if count == 1 {
            println!();
            println!("按回车键退出…");
            let _ = std::io::stdin().read_line(&mut String::new());
        }
    }
}
