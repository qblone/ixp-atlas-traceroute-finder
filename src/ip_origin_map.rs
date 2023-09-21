use std::net::IpAddr;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

pub struct SearchResult {
    pub ip_address: String,
    pub network: String,
    pub origin: String,
}

pub fn search_ip_addresses(table: &IpNetworkTable<IpNetwork>, ip_addresses: &[String]) -> Vec<SearchResult> {
    ip_addresses
        .iter()
        .map(|ip_address| {
            let ip_addr: IpAddr = ip_address.parse().unwrap();
            match table.longest_match(ip_addr) {
                Some((network, origin)) => SearchResult {
                    ip_address: ip_address.clone(),
                    network: network.to_string(),
                    origin: origin.clone(),
                },
                None => SearchResult {
                    ip_address: ip_address.clone(),
                    network: String::from("No match found"),
                    origin: String::from("Unknown"),
                },
            }
        })
        .collect()
}
