use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use ip_network::{IpNetwork};
use ip_network_table::IpNetworkTable;

fn build_network_table(file_path: &str) -> ip_network_table::IpNetworkTable<ip_network::IpNetwork> {
    let mut table = ip_network_table::IpNetworkTable::new();

    let file = std::fs::File::open(file_path).expect("Failed to open file");
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        if let Ok(line) = line {
            if line.starts_with('%') || line.is_empty() {
                continue; // Ignore comments and empty lines
            }

            let mut parts = line.split_whitespace();
            if let (Some(origin_str), Some(prefix_str), _) = (parts.next(), parts.next(), parts.next()) {
                if let Ok(prefix) = prefix_str.parse::<ip_network::IpNetwork>() {
                    table.insert(prefix, origin_str.to_string());
                }
            }
        }
    }

    table
}


