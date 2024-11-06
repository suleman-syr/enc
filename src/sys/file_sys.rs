
use mime_guess::from_path;
use std::path::Path;
use std::fs;

#[allow(dead_code)]
pub struct FILESYS {
    pub path: String,
    pub name: Option<String>,
    pub type_of: String,
    pub ext: Option<String>,
    pub size : u64,
    pub is_encrypted: bool,
}

impl FILESYS {
    #[allow(dead_code)]
    pub fn new(path: &str) -> FILESYS {
        let path = Path::new(path);
        let name = path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.to_string());

        let ext = path.extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_string());

        let type_of = match ext {
            Some(ref e) => format!("{}", e),
            None => FILESYS::guess_mime_type(path),
        };

        let size = match fs::metadata(path) {
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        };

        FILESYS {
            path: path.to_string_lossy().to_string(),
            name,
            ext,
            type_of,
            size,
            is_encrypted: false,
        }
    }
    #[allow(dead_code)]
    fn guess_mime_type(path: &Path) -> String {
        let mime_type = from_path(path).first_or_octet_stream();
        mime_type.essence_str().to_string()
    }
    #[allow(dead_code)]
    pub fn convert_size_mb(&self) -> f64 {
        let size = self.size as f64 / 1_048_576.0;

        size
    }
    #[allow(dead_code)]
    pub fn convert_size_kb(&self) -> f64 {
        let size = self.size as f64 / 1024.0;

        size
    }
}