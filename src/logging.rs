use tracing_subscriber::EnvFilter;

pub fn init(silent: bool, verbose: bool) {
    let level = if silent {
        "warn"
    } else if verbose {
        "debug"
    } else {
        "info"
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("lancer_subfinder={level}")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
