mod netif_mon;

use netif_mon::NetIfMon;

fn main() {
    
    let nm = NetIfMon::new();
    println!("{}", nm.to_string());
}
