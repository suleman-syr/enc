use sysinfo::Pid;
use sysinfo::{Disks, System};

pub struct Profile {
    pub os_version: String,
    pub host_name: String,
    pub disks: Vec<String>,
    pub name: String,
}

impl Profile {
    pub fn new() -> Self {
        let mut disks = Vec::new();
        let disks_exist = Disks::new_with_refreshed_list();

        for disk in disks_exist.list() {
            disks.push(disk.name().to_str().unwrap_or_else(|| "Unkown").to_string());
        }

        let os_version: String = System::os_version().unwrap_or_else(|| "Unkown".to_string());
        let host_name: String = System::host_name().unwrap_or_else(|| "Unkown".to_string());

        let name: String = System::name().unwrap_or_else(|| "Unkown".to_string());

        Self {
            os_version: os_version,
            host_name: host_name,
            disks: disks,
            name: name,
        }
    }
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

pub fn list_process() -> Vec<(Pid, String)> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut result = Vec::new();

    for (pid, process) in sys.processes() {
        result.push((
            *pid,
            process
                .name()
                .to_str()
                .expect("Error while to_string process")
                .to_string(),
        ));
    }

    result
}

pub fn get_process_byid(name: String) -> Option<Pid> {
    for (pid, process) in list_process() {
        if process == name {
            return Some(pid);
        }
    }
    None
}

pub fn kill_process_byid(id: Pid) {
    let s = System::new_all();
    if let Some(process) = s.process(id) {
        process.kill();
    }
}

pub fn kill_process_byname(name: String) {
    for (pid, process) in list_process() {
        if process == name {
            kill_process_byid(pid);
        }
    }
}
