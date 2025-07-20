use selenia_core::config::ServerConfig;
use selenia_core::locale::register_locale;
use selenia_core::{log_info, log_error};
use selenia_http::run_server;
use std::collections::HashMap;

fn main() {
    // Load configuration.
    let cfg = match ServerConfig::load_from_yaml("config.yaml")
        .or_else(|_| ServerConfig::load_from_file("config.txt")) {
        Ok(c) => c,
        Err(e) => {
            log_error!("Config load failure: {:?}", e);
            std::process::exit(1);
        }
    };

    // Register English locale.
    let mut en = HashMap::new();
    en.insert("http.not_found".to_string(), "404 Not Found".to_string());
    en.insert(
        "http.method_not_allowed".to_string(),
        "405 Method Not Allowed".to_string(),
    );
    register_locale("en", en);

    // Register Japanese locale.
    let mut ja = HashMap::new();
    ja.insert("http.not_found".to_string(), "404 見つかりません".to_string());
    ja.insert(
        "http.method_not_allowed".to_string(),
        "405 許可されていないメソッドです".to_string(),
    );
    register_locale("ja", ja);

    log_info!("Starting Selenia Web Server using first listen address: {}", cfg.listen.get(0).cloned().unwrap_or_default());
    if let Err(e) = run_server(cfg) {
        log_error!("Server terminated: {}", e);
    }
} 