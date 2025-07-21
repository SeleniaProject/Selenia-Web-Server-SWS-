use std::collections::HashMap;
use std::sync::{Once, RwLock};

// Manual once-init static to avoid external crates.
static mut LOCALES: Option<RwLock<HashMap<String, HashMap<String, String>>>> = None;
static INIT: Once = Once::new();

fn get_locales() -> &'static RwLock<HashMap<String, HashMap<String, String>>> {
    unsafe {
        INIT.call_once(|| {
            LOCALES = Some(RwLock::new(HashMap::new()));
        });
        LOCALES.as_ref().expect("LOCALES initialized")
    }
}

/// Register a locale by name along with its string table.
pub fn register_locale<S: Into<String>>(locale: S, strings: HashMap<String, String>) {
    let locales = get_locales();
    locales.write().unwrap().insert(locale.into(), strings);
}

/// Fetch a translated string for `key` in `locale`.
/// Returns the key itself when translation is missing.
pub fn translate(locale: &str, key: &str) -> String {
    let locales = get_locales();
    locales
        .read()
        .unwrap()
        .get(locale)
        .and_then(|map| map.get(key))
        .cloned()
        .unwrap_or_else(|| key.to_string())
} 