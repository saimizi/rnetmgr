mod netif_mon;
use netif_mon::NetIfMon;

#[tokio::main]
async fn main() {
    let thread = match NetIfMon::start().await {
        Ok(thread) => thread,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = thread.await {
        eprintln!("Error: {}", e);
    }
}
