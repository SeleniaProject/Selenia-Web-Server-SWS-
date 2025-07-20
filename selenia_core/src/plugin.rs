//! Dynamic plugin loader skeleton (Hot-Reload). No external crates.
//! At this stage we only support `cdylib` plugins exporting a `sws_plugin_init` symbol.

use std::collections::HashMap;
use std::ffi::{CString, c_void};
use std::path::Path;
use std::sync::RwLock;

#[cfg(unix)] use libc::{dlopen, dlsym, dlclose, RTLD_NOW};
#[cfg(windows)] use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress, FreeLibrary};

static PLUGINS: RwLock<HashMap<String, PluginHandle>> = RwLock::new(HashMap::new());

pub type PluginInit = unsafe extern "C" fn();

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
        let init_sym = CString::new("sws_plugin_init").unwrap();
        let init_ptr = {
            #[cfg(unix)] { dlsym(handle, init_sym.as_ptr()) }
            #[cfg(windows)] { GetProcAddress(handle as _, init_sym.as_ptr()) as _ }
        };
        if init_ptr.is_null() {
            #[cfg(unix)] { dlclose(handle); }
            #[cfg(windows)] { FreeLibrary(handle as _); }
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "symbol not found"));
        }
        let init: PluginInit = std::mem::transmute(init_ptr);
        init(); // call plugin init
        PLUGINS.write().unwrap().insert(path.as_ref().to_string_lossy().into_owned(), PluginHandle{name:path.as_ref().to_string_lossy().into_owned(), lib:handle, init});
    }
    Ok(())
}

/// Unload plugin by name.
pub fn unload_plugin(name: &str) {
    PLUGINS.write().unwrap().remove(name);
} 