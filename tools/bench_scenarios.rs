use std::process::Command;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: bench_scenarios <wrk2|h2load|quicperf> [url]");
        std::process::exit(1);
    }
    let scenario = &args[1];
    let url = args.get(2).cloned().unwrap_or_else(|| "http://127.0.0.1/".into());
    match scenario.as_str() {
        "wrk2" => run_wrk2(&url),
        "h2load" => run_h2load(&url),
        "quicperf" => run_quicperf(&url),
        _ => {
            eprintln!("Unknown scenario '{}'. Use wrk2|h2load|quicperf", scenario);
            std::process::exit(1);
        }
    }
}

fn run_wrk2(url: &str) {
    let cmd = Command::new("wrk2")
        .args(["-t32", "-c1000000", "-d30s", "-R400000", url])
        .status().expect("failed to spawn wrk2");
    if !cmd.success() { eprintln!("wrk2 exited with {}", cmd); }
}

fn run_h2load(url: &str) {
    let cmd = Command::new("h2load")
        .args(["-n1000000", "-c64000", "--h1", url])
        .status().expect("failed to spawn h2load");
    if !cmd.success() { eprintln!("h2load exited with {}", cmd); }
}

fn run_quicperf(url: &str) {
    let cmd = Command::new("quicperf")
        .args(["-t30", "-c5000", url])
        .status().expect("failed to spawn quicperf");
    if !cmd.success() { eprintln!("quicperf exited with {}", cmd); }
} 