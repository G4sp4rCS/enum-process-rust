/// Función para imprimir todos los procesos en ejecución en Windows

    use windows_sys::Win32::System::ProcessStatus::{EnumProcesses, EnumProcessModules, GetModuleBaseNameW};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE};

fn PrintProcesses() -> bool {


    const MAX_PROCESSES: usize = 1024 * 2;
    const MAX_PATH: usize = 260;

    unsafe {
        let mut processes: [u32; MAX_PROCESSES] = [0; MAX_PROCESSES];
        let mut bytes_returned: u32 = 0;

        // Get the array of PIDs
        if EnumProcesses( // si falla
            processes.as_mut_ptr(),
            (processes.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        ) == 0
        {
            eprintln!("[!] EnumProcesses Failed With Error : {}", GetLastError());
            return false;
        }

        // Calculate the number of processes
        let num_processes = (bytes_returned as usize) / std::mem::size_of::<u32>();
        println!("[i] Number Of Processes Detected : {}", num_processes);

        // para cada proceso
        for i in 0..num_processes {
            let pid = processes[i];

            // If process is not NULL
            if pid != 0 {
                // then open a process handle
                let h_process: HANDLE = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    0, // FALSE
                    pid,
                );

                if h_process != 0 {
                    let mut h_module: HMODULE = 0;
                    let mut bytes_needed: u32 = 0;

                    // Get a handle of a module in the process
                    if EnumProcessModules(
                        h_process,
                        &mut h_module,
                        std::mem::size_of::<HMODULE>() as u32,
                        &mut bytes_needed,
                    ) == 0
                    {
                        println!(
                            "[!] EnumProcessModules Failed [ At Pid: {} ] With Error : {}",
                            pid,
                            GetLastError()
                        );
                    } else {
                        let mut process_name: [u16; MAX_PATH] = [0; MAX_PATH];

                        // Get the name of the process
                        if GetModuleBaseNameW(
                            h_process,
                            h_module,
                            process_name.as_mut_ptr(),
                            MAX_PATH as u32,
                        ) == 0
                        {
                            println!(
                                "[!] GetModuleBaseName Failed [ At Pid: {} ] With Error : {}",
                                pid,
                                GetLastError()
                            );
                        } else {
                            // Convert UTF-16 to String and print
                            let name_len = process_name.iter().position(|&x| x == 0).unwrap_or(MAX_PATH);
                            let name = String::from_utf16_lossy(&process_name[..name_len]);
                            println!("[{:03}] Process \"{}\" - Of Pid : {}", i, name, pid);
                        }
                    }

                    // Close process handle
                    CloseHandle(h_process);
                }
            }
        }
    }

    true
}


fn GetRemoteProcessHandle(process_name: &str) -> Option<(u32, HANDLE)> {

    const MAX_PROCESSES: usize = 1024 * 2;
    const MAX_PATH: usize = 260;

    unsafe {
        let mut processes: [u32; MAX_PROCESSES] = [0; MAX_PROCESSES];
        let mut bytes_returned: u32 = 0;

        // Get the array of PIDs
        if EnumProcesses(
            processes.as_mut_ptr(),
            (processes.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        ) == 0
        {
            eprintln!("[!] EnumProcesses Failed With Error : {}", GetLastError());
            return None;
        }

        // Calculate the number of processes
        let num_processes = (bytes_returned as usize) / std::mem::size_of::<u32>();
        println!("[i] Number Of Processes Detected : {}", num_processes);

        // Convert target process name to UTF-16
        let target_name_utf16: Vec<u16> = process_name.encode_utf16().collect();

        for i in 0..num_processes {
            let pid = processes[i];

            if pid != 0 {
                let h_process: HANDLE = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    0,
                    pid,
                );

                if h_process != 0 {
                    let mut h_module: HMODULE = 0;
                    let mut bytes_needed: u32 = 0;

                    if EnumProcessModules(
                        h_process,
                        &mut h_module,
                        std::mem::size_of::<HMODULE>() as u32,
                        &mut bytes_needed,
                    ) != 0
                    {
                        let mut process_name_buf: [u16; MAX_PATH] = [0; MAX_PATH];

                        if GetModuleBaseNameW(
                            h_process,
                            h_module,
                            process_name_buf.as_mut_ptr(),
                            MAX_PATH as u32,
                        ) != 0
                        {
                            // Find the length of the process name
                            let name_len = process_name_buf.iter().position(|&x| x == 0).unwrap_or(MAX_PATH); // Find the null terminator

                            
                            // Compare UTF-16 strings
                            if name_len == target_name_utf16.len() 
                                && process_name_buf[..name_len] == target_name_utf16[..] 
                            {
                                let name = String::from_utf16_lossy(&process_name_buf[..name_len]);
                                println!("[+] FOUND \"{}\" - Of Pid : {}", name, pid);
                                return Some((pid, h_process));
                            }
                        }
                    }

                    CloseHandle(h_process);
                }
            }
        }
    }

    None
}

fn main() {
    if PrintProcesses() {
        println!("Process enumeration completed successfully.");
        // Example usage of GetRemoteProcessHandle
        // we search the explorer's pid
        if let Some((pid, handle)) = GetRemoteProcessHandle("Explorer.EXE") {
            println!("Found explorer.exe with PID: {} and handle: {:?}", pid, handle);
            // Close the handle after use
            unsafe { CloseHandle(handle) };
        } else {
            println!("explorer.exe not found.");
        }

    } else {
        println!("Process enumeration failed.");
    }
}
