//! Dynamic plugin loader skeleton (Hot-Reload). No external crates.
//! At this stage we only support `cdylib` plugins exporting a `sws_plugin_init` symbol.

use std::collections::HashMap;
use std::ffi::{CString, c_void};
use std::path::Path;
use std::sync::{RwLock, OnceLock};

#[cfg(unix)] use libc::{dlopen, dlsym, dlclose, RTLD_NOW};
#[cfg(windows)] use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress, FreeLibrary};

static PLUGINS: OnceLock<RwLock<HashMap<String, PluginHandle>>> = OnceLock::new();

fn plugins() -> &'static RwLock<HashMap<String, PluginHandle>> {
    PLUGINS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub type PluginInit = unsafe extern "C" fn();

#[repr(C)]
pub struct SwsPluginV1 {
    pub name: *const i8,
    pub version: u32,
    pub on_load: PluginInit,
    pub on_request: *const c_void, // not used yet
    pub on_unload: PluginInit,
}

const ABI_VERSION: u32 = 1;

struct PluginHandle {
    name: String,
    lib: *mut c_void,
    init: PluginInit,
}

unsafe impl Send for PluginHandle {}
unsafe impl Sync for PluginHandle {}

impl Drop for PluginHandle {
    fn drop(&mut self) {
        unsafe {
            #[cfg(unix)] { dlclose(self.lib); }
            #[cfg(windows)] { FreeLibrary(self.lib as _); }
        }
    }
}

/// Load plugin dynamic library and call its init symbol.
pub fn load_plugin<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    let cname = CString::new(path.as_ref().to_string_lossy().into_owned()).unwrap();
    unsafe {
        let handle = {
            #[cfg(unix)] { dlopen(cname.as_ptr(), RTLD_NOW) }
            #[cfg(windows)] { LoadLibraryA(cname.as_ptr()) as _ }
        };
        if handle.is_null() { return Err(std::io::Error::new(std::io::ErrorKind::Other, "dlopen failed")); }
        // Prefer new ABI symbol first.
        let entry_sym = CString::new("sws_plugin_entry_v1").unwrap();
        let entry_ptr = {
            #[cfg(unix)] { dlsym(handle, entry_sym.as_ptr()) }
            #[cfg(windows)] { GetProcAddress(handle as _, entry_sym.as_ptr()) as _ }
        };

        let init_ptr = if !entry_ptr.is_null() {
            let entry:&SwsPluginV1 = &*(entry_ptr as *const SwsPluginV1);
            if entry.version != ABI_VERSION { dlclose(handle); return Err(std::io::Error::new(std::io::ErrorKind::Other, "ABI version mismatch")); }
            (entry.on_load)();
            entry.on_unload as *const c_void
        } else {
            // Fallback to legacy symbol.
            let init_sym = CString::new("sws_plugin_init").unwrap();
            let p = {
                #[cfg(unix)] { dlsym(handle, init_sym.as_ptr()) }
                #[cfg(windows)] { GetProcAddress(handle as _, init_sym.as_ptr()) as _ }
            };
            if p.is_null() {
                #[cfg(unix)] { dlclose(handle); }
                #[cfg(windows)] { FreeLibrary(handle as _); }
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "required symbol missing"));
            }
            let init: PluginInit = std::mem::transmute(p);
            init();
            p
        };

        let _ = init_ptr; // suppress warning for now

        // Store handle without keeping function pointer.
        plugins().write().unwrap().insert(path.as_ref().to_string_lossy().into_owned(), PluginHandle{name:path.as_ref().to_string_lossy().into_owned(), lib:handle, init});
    }
    Ok(())
}

/// Unload plugin by name.
pub fn unload_plugin(name: &str) {
    plugins().write().unwrap().remove(name);
}

/// Validate a plugin by loading it and immediately unloading; ensures required symbol exists.
pub fn validate_plugin<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    let path_ref = path.as_ref();
    // Attempt to load the plugin. This will store it in the global map.
    load_plugin(&path_ref)?;
    // Immediately unload so we do not keep state during validation.
    unload_plugin(&path_ref.to_string_lossy());
    Ok(())
}

/// Install a plugin: copy the library into the `plugins/` directory and load it.
/// Returns an error if copy or loading fails.
pub fn install_plugin<P: AsRef<Path>>(src: P) -> std::io::Result<()> {
    let src_path = src.as_ref();
    let filename = src_path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid source path"))?;
    let plugins_dir = std::path::Path::new("plugins");
    std::fs::create_dir_all(plugins_dir)?;
    let dst_path = plugins_dir.join(filename);

    // Overwrite if already exists to support upgrades.
    std::fs::copy(src_path, &dst_path)?;

    // Load the newly installed plugin so it becomes active immediately.
    load_plugin(&dst_path)
} 