use sysinfo::{
     Disks,  System,
};
use std::io;
use sysinfo::{Pid , Process};
use std::fmt::Error;
#[derive(Debug)]
pub struct Victem {
	pub os_version : String,
	// pub process_runing : Vec<(Pid, Process)>,
	pub host_name : String,
	pub disks_exists : Vec<String>,
}


impl Victem {
	pub fn new() -> Self {
		let mut sys = System::new_all();

		sys.refresh_all();
		let os_version : String = System::os_version()
										.unwrap_or_else( || "Unkown".to_string());
		let host_name  : String = System::host_name()
										.unwrap_or_else( || "Unkown".to_string());

		let process_runing = Self::list_process();

		let mut disks_exists = Vec::new();
		let disks = Disks::new_with_refreshed_list();
		for disk in &disks {
        	disks_exists.push(disk.mount_point().to_string_lossy().into_owned());
		}

		Self {
			os_version,
			host_name,
			// process_runing,
			disks_exists,
		}
	}

	pub fn list_process() -> Vec<(&'static Pid, &'static Process)>{
		let mut sys = System::new_all();

		sys.refresh_all();

		let mut process_runing = Vec::new();
		for (pid , process) in sys.processes() {
			let process_info = (pid, process );

			process_runing.push(process_info);
		}
		process_runing
	}

	pub fn kill_process_by_id( id : String) -> Result<() , io::Error> {
			Ok(())
	}

	pub fn kill_process_by_name(name : String) -> Result<() , io::Error> {
		for (pid , process) in Self::list_process() {
			if process.name() == "firefox" {
				process.kill();
				return Ok(())
			}
		}

		return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid RSA Key"));
	}

}