mod model;
mod utils;

use std::collections::HashSet;
use clap::Parser;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io;
use std::io::Write;
use std::path::Path;
use csv::ReaderBuilder;

use std::fs::OpenOptions;
use serde_json::json;

use ip_network_table::IpNetworkTable;
use ip_network::IpNetwork;


use reqwest;
use serde::Deserialize;
extern crate tokio;
use tokio::time::{sleep, Duration};



use chrono::{DateTime, Utc};
//use model::{AtlasTraceroute, AtlasTracerouteHop, AtlasTracerouteReply};
use std::net::IpAddr;
use json_parser::formats::atlas::AtlasReader;


use std::error::Error;
//use utils::empty_string_as_none;
#[derive(Debug)]
struct SimplifiedTraceroute {
    dst_addr: Option<IpAddr>,
    from: Option<String>,
    msm_id: u64,
    prb_id: u64,
    src_addr: Option<IpAddr>,
    timestamp: DateTime<Utc>,
    unique_pairs: Vec<(u8, Option<String>)>,
}

#[derive(Debug)]
struct SearchResult {
    ip_addr: String,
    network: String,
    origin: String,
}


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(long, short, action)]    
    add_cc: bool,
}


#[derive(Deserialize)]
struct Geolocation {
    location: Location,
}

#[derive(Deserialize)]
struct Location {
    country_code_alpha2: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IXP {
    name: String,
    prefix_v4: String,
    country: String,
    region: String,
}


enum IpSource {
    IpMap,  // Note the name change to match the function
    IpInfo,
}

async fn get_country_code_from_ipmap(ip: &str) -> Result<String, reqwest::Error> {
    let ipmap_url = format!("https://ipmap-api.ripe.net/v1/locate/{}/best", ip);
    let response: Geolocation = reqwest::get(&ipmap_url).await?.json().await?;
    Ok(response.location.country_code_alpha2.unwrap_or("".to_string()))
}

fn load_ixp_prefixes_from_csv(filename: &str) -> io::Result<HashSet<IpNetwork>> {
    let mut rdr = ReaderBuilder::new().from_path(filename)?;
    let mut prefixes = HashSet::new();

    for result in rdr.deserialize() {
        let record: IXP = result?;
        let prefix: IpNetwork = record.prefix_v4.parse().expect("Invalid IP Prefix in CSV");
        prefixes.insert(prefix);
    }

    Ok(prefixes)
}


async fn get_country_code_from_ipinfo(ip: &str) -> Result<String, reqwest::Error> {
    let ipinfo_url = format!("https://ipinfo.io/{}/country", ip);
    match reqwest::get(&ipinfo_url).await {
        Ok(resp) => {
            match resp.text().await {
                Ok(country_code) => {
                    let trimmed_code = country_code.trim();
                    if trimmed_code.len() == 2 {
                        Ok(trimmed_code.to_string())
                    } else {
                        Ok("".to_string())  // return empty string if the response isn't a valid country code
                    }
                }
                Err(_) => Ok("".to_string()),  // return empty string if there's an error in parsing response
            }
        }
        Err(_) => Ok("".to_string()),  // return empty string if there's an error in fetching data
    }
}

async fn get_country_code(ip: &str, source: IpSource) -> Result<String, reqwest::Error> {
    sleep(Duration::from_millis(100)).await;  // Introducing a 100ms delay, hopefully won't get blacklisted

    match source {
        IpSource::IpMap => get_country_code_from_ipmap(ip).await,
        IpSource::IpInfo => get_country_code_from_ipinfo(ip).await,
    }
}


fn main() {

    let table = build_network_table("/data/qlone/topology-measurements/riswhois/riswhoisdump.IPv4").expect("Failed to build network table");

    let directory_path = "/data/qlone/topology-measurements/raw-traceroutes/";
    let output_directory_path = "/data/qlone/topology-measurements/ixps/";
    
    // Iterate over each file in the directory
    let directory_entries = std::fs::read_dir(directory_path).expect("Failed to read directory");

    for entry_result in directory_entries {
        if let Ok(entry) = entry_result {
            let file_path = entry.path();
            if file_path.is_file() && file_path.extension() == Some(std::ffi::OsStr::new("json")) {
                println!("Processing file: {}", file_path.display());

                // Get the filename without the extension
                let file_stem = file_path.file_stem().expect("Failed to get file stem")
                    .to_string_lossy()
                    .into_owned();

                // Build the output file path
                let output_file_path = format!("{}{}.json", output_directory_path, file_stem);
                let output_file_path = std::path::Path::new(&output_file_path);

                match parse_traceroutes_file(&file_path.to_string_lossy()) {
                    Ok(traceroutes) => {
                        let total_objects = traceroutes.len();
                        println!("Total Objects in Traceroute: {}", total_objects);
                        for traceroute in traceroutes {
                            let simplified_traceroute: SimplifiedTraceroute = simplify_traceroute(traceroute);
                            //print_simplified_traceroute(simplified_traceroute, &table);
                            if let Err(err) = write_simplified_traceroute_to_json(simplified_traceroute, &table, &output_file_path) {
                                eprintln!("Failed to write to JSON: {}", err);
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("Error: {}", error);
                    }
                }
            }
        }
    }
}


fn parse_traceroutes_file(file_path: &str) -> io::Result<Vec<model::AtlasTraceroute>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let atlas_reader = AtlasReader::new(reader);
    let traceroutes: Vec<model::AtlasTraceroute> = atlas_reader
        .filter_map(Result::ok)
        .map(|atlas_traceroute| atlas_traceroute.into())
        .collect();
    Ok(traceroutes)
}

fn is_ixp_inpath(traceroute: &SimplifiedTraceroute, table: &IpNetworkTable<String>) -> bool {
    for (_, from) in &traceroute.unique_pairs {
        let (converted_ip, _) = convert_to_ip_or_keep_string(from.as_deref());
        if let Some(ip) = converted_ip {
            let matched = longest_match_lookup(Some(ip), table);
            if !matched.network.is_empty() {
                return true;
            }

           
        }
    }
    false
}




fn simplify_traceroute(atlas_traceroute: model::AtlasTraceroute) -> SimplifiedTraceroute {
    let mut unique_pairs = HashSet::new();

    for hop in &atlas_traceroute.result {
        for reply in &hop.result {
            unique_pairs.insert((hop.hop, reply.from.clone()));

        }
    }

    let mut unique_pairs_vec: Vec<(u8, Option<String>)> = unique_pairs.into_iter().collect();
    unique_pairs_vec.sort_by_key(|&(hop, _)| hop);

    SimplifiedTraceroute {
        dst_addr: atlas_traceroute.dst_addr,
        from: atlas_traceroute.from,
        msm_id: atlas_traceroute.msm_id,
        prb_id: atlas_traceroute.prb_id,
        src_addr: atlas_traceroute.src_addr,
        timestamp: atlas_traceroute.timestamp,
        unique_pairs: unique_pairs_vec,
    }
}


fn build_network_table(file_path: &str) -> Result<IpNetworkTable<String>, Box<dyn std::error::Error>> {
    let mut table = IpNetworkTable::new();
    // Read the file line by line and insert network-prefix-origin triples into the table
    let file = File::open(file_path).expect("Failed to open file");
    let reader = BufReader::new(file);
    for line in reader.lines() {
        if let Ok(line) = line {
            if line.starts_with('%') || line.is_empty() {
                continue; // Ignore comments and empty lines
            }

            let mut parts = line.split_whitespace();
            if let (Some(origin_str), Some(prefix_str), _) = (parts.next(), parts.next(), parts.next()) {
                if let Ok(prefix) = prefix_str.parse::<IpNetwork>() {
                    table.insert(prefix, origin_str.to_string());
                }
            }
        }
    }

    Ok(table)
}


fn convert_to_ip_or_keep_string(s: Option<&str>) -> (Option<IpAddr>, Option<String>) {
    if let Some(ip_str) = s {
        match ip_str.parse::<IpAddr>() {
            Ok(ip) => (Some(ip), None),
            Err(_) => (None, Some(ip_str.to_string())),
        }
    } else {
        (None, None)
    }
}


// ... (rest of the code)



/// Returns a `SearchResult` structure which contains the IP address, network, and origin
/// If the IP address is private, unspecified or belongs to a non-routable network (0.0.0.0/0), 
/// then it returns empty strings for network and origin.
///
/// # Arguments
///
/// * `ip_addr` - An Option<IpAddr> which may contain the IP address to be looked up.
/// * `table` - A reference to an IP network table that will be used for the lookup.
///
/// # Returns
///
/// * `Option<SearchResult>` - Contains the SearchResult structure if the input `ip_addr` was Some. If `ip_addr` was None, returns None.
fn longest_match_lookup(ip_addr: Option<IpAddr>, table: &IpNetworkTable<String>) -> SearchResult {
    match ip_addr {
        Some(IpAddr::V4(addr)) => {
            if addr.is_private() || addr.is_unspecified() {
                return SearchResult {
                    ip_addr: addr.to_string(),
                    network: String::from(""),
                    origin: String::from(""),
                };
            }

            match table.longest_match(IpAddr::V4(addr)) {
                Some((network, origin)) => SearchResult {
                    ip_addr: addr.to_string(),
                    network: network.to_string(),
                    origin: origin.clone(),
                },
                None => SearchResult {
                    ip_addr: addr.to_string(),
                    network: String::from(""),
                    origin: String::from(""),
                },
            }
        }
        Some(_) => {
            panic!("Unexpected IPv6 address encountered!");
        }
        None => SearchResult {
            ip_addr: String::from(""),
            network: String::from(""),
            origin: String::from(""),
        },
    }
}








fn write_simplified_traceroute_to_json(
    traceroute: SimplifiedTraceroute,
    table: &IpNetworkTable<String>,
    output_file: &Path,
) -> Result<(), Box<dyn Error>> {
    
    // Check if the traceroute contains any IXP prefix.
    if !is_ixp_inpath(&traceroute, table) {
        return Ok(());
    }

    let (dst_addr, _) = convert_to_ip_or_keep_string(None); // since dst_addr is already an IpAddr
    let (from_addr, _) = convert_to_ip_or_keep_string(traceroute.from.as_deref());
    let (src_addr, _) = convert_to_ip_or_keep_string(None); // since src_addr is already an IpAddr
    let dst_addr_result = longest_match_lookup(dst_addr, table);

    let from_result = longest_match_lookup(from_addr, table);
    let src_addr_result = longest_match_lookup(src_addr, table);

    let mut hops = Vec::new();

    //geo-location
    let runtime = tokio::runtime::Runtime::new()?;
    let from_country = runtime.block_on(get_country_code(&from_addr.ok_or("Failed to get 'from' address")?.to_string(), IpSource::IpInfo))?;
    let src_country = runtime.block_on(get_country_code(&src_addr.ok_or_else(|| format!("Failed to get source address: {:?}", src_addr))?.to_string(), IpSource::IpInfo))?;

    //let src_country = runtime.block_on(get_country_code(&src_addr.ok_or("Failed to get source address")?.to_string(), IpSource::IpInfo))?;

    for (hop, from) in &traceroute.unique_pairs {
        let (converted_ip, failed_conversion) = convert_to_ip_or_keep_string(from.as_deref());
        let mut hop_cc = "".to_string(); // Default value

        if let Some(ip) = converted_ip {
            let search_result = longest_match_lookup(Some(ip), table);
            let ip_str = ip.to_string();

            match runtime.block_on(get_country_code(&ip_str, IpSource::IpInfo)) {
                Ok(country_code) => {
                    hop_cc = country_code;
                }
                Err(e) => {
                    println!("Error while getting country code: {}", e);
                }
            }

            hops.push(json!({
                "hop_number": hop,
                "ip_addr": search_result.ip_addr,
                "network": search_result.network,
                "origin": search_result.origin,
                "hop_cc": hop_cc,
            }));
        }

        if let Some(failed_ip) = failed_conversion {
            hops.push(json!({
                "hop_number": hop,
                "ip_addr": failed_ip,
                "network": "",
                "origin": "",
                "hop_cc": hop_cc,
            }));
        }
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(output_file)?;

    let data = json!({
        "msm_id": traceroute.msm_id,
        "prb_id": traceroute.prb_id,
        "timestamp": traceroute.timestamp,
        "destination": {
            "ip_addr": dst_addr_result.ip_addr,
            "network": dst_addr_result.network,
            "origin": dst_addr_result.origin
        },
        "from": {
            "ip_addr": from_result.ip_addr,
            "network": from_result.network,
            "origin": from_result.origin,
            "from_cc": from_country
        },
        "source": {
            "ip_addr": src_addr_result.ip_addr,
            "network": src_addr_result.network,
            "origin": src_addr_result.origin,
            "src_cc": src_country
        },
        "hops": hops,
    });

    writeln!(file, "{}", serde_json::to_string(&data)?)?;
    Ok(())
}








/* fn print_simplified_traceroute(traceroute: SimplifiedTraceroute,  table: &IpNetworkTable<String>) {
    println!("-----------------------------------------");
    println!("Measurement ID: {}", traceroute.msm_id);
    println!("Probe ID: {}", traceroute.prb_id);
    println!("Timestamp: {:?}", traceroute.timestamp);

    // Perform the lookup for destination, from and source addresses
    let dst_addr_result = longest_match_lookup(traceroute.dst_addr, table);
    let from_result = longest_match_lookup(traceroute.from, table);
    let src_addr_result = longest_match_lookup(traceroute.src_addr, table);

    if let Some(result) = dst_addr_result {
        println!("Destination: {},{},{}", result.ip_addr,result.network,result.origin);
    }

    if let Some(result) = from_result {
        println!("From: {},{},{}", result.ip_addr,result.network,result.origin);
    }

    if let Some(result) = src_addr_result {
        println!("Source: {},{},{}", result.ip_addr,result.network,result.origin);
    }

    for (hop, from) in traceroute.unique_pairs {
        if let Some(search_result) = longest_match_lookup(from, table) {
            println!("{},{},{},{}", hop, search_result.ip_addr, search_result.network, search_result.origin);
        }
    }
}
 */