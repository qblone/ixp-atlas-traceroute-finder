mod model;
mod utils;

use clap::Parser;
use std::collections::HashSet;

use csv::ReaderBuilder;
use serde_json::json;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use reqwest;
use serde::Deserialize;
extern crate tokio;
use tokio::time::{sleep, Duration};

use chrono::{DateTime, Utc};
//use model::{AtlasTraceroute, AtlasTracerouteHop, AtlasTracerouteReply};
//use std::net::IpAddr;
use json_parser::formats::atlas::AtlasReader;

use std::error::Error;
//use utils::empty_string_as_none;
#[derive(Debug)]
struct SimplifiedTraceroute {
    dst_addr: Option<IpAddr>,
    from_addr: Option<IpAddr>,
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

#[derive(Debug, Deserialize)]
struct Geolocation {
    location: Location,
}

#[derive(Debug, Deserialize)]
struct Location {
    countryCodeAlpha2: Option<String>, // Use the same field name as in the JSON
}

#[derive(Debug, Deserialize)]
struct IXP {
    name: String,
    prefix_v4: String,
    country: String,
    region: String,
}

enum IpSource {
    IpMap, // Note the name change to match the function
    IpInfo,
}

async fn get_country_code_from_ipmap(ip: &str) -> Result<String, reqwest::Error> {
    let ipmap_url = format!("https://ipmap-api.ripe.net/v1/locate/{}/best", ip);
    let response: Geolocation = reqwest::get(&ipmap_url).await?.json().await?;
   // println!("Response body: {:?}", response); // Debug print the response body

    Ok(response
        .location
        .countryCodeAlpha2
        .unwrap_or("".to_string()))
}

// Define a struct to store prefix and country code
struct PrefixCountry {
    prefix: String,
    country_code: String,
}

// Define a struct to store IPv4 and IPv6 lookup tables
struct GeolocationLookup {
    ipv4_table: Vec<PrefixCountry>,
    ipv6_table: Vec<PrefixCountry>,
}

fn load_ixp_prefixes_from_csv(
    filename: &str,
    table: &mut IpNetworkTable<String>,
) -> Result<(), Box<dyn Error>> {
    let mut rdr = ReaderBuilder::new().from_path(filename)?;

    for result in rdr.deserialize() {
        let record: IXP = result?;
        let prefix: IpNetwork = record.prefix_v4.parse()?;
        let ixp_name = record.name.clone();
        table.insert(prefix, ixp_name);
    }

    Ok(())
}

impl GeolocationLookup {
    // Create a new instance of GeolocationLookup and populate it from a CSV file
    fn from_csv_file(file_path: &str) -> Result<Self, Box<dyn Error>> {
        let mut ipv4_table = Vec::new();
        let mut ipv6_table = Vec::new();

        let file = File::open(file_path)?;
        let reader = io::BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 7 {
                let prefix = parts[0].to_string();
                let prefix_clone = prefix.clone();
                //let country_code = parts[5].to_string();
                let prefix = parts[0].to_string();
                let country_code = parts[5].to_string();
                let prefix_country = PrefixCountry {
                    prefix,
                    country_code,
                };
                if let Ok(_ip) = prefix_clone.parse::<IpAddr>() {
                    // Now you can use the `prefix` variable here without issues.
                    if prefix_clone.contains(':') {
                        ipv6_table.push(prefix_country);
                    } else {
                        ipv4_table.push(prefix_country);
                    }
                }
            }
        }

        Ok(Self {
            ipv4_table,
            ipv6_table,
        })
    }

    // Lookup function to find the country code based on the IP address
    fn lookup_country_code(&self, ip: &IpAddr) -> String {
        let ip_str = ip.to_string();
        self.longest_prefix_match(&ip_str)
    }

    // Perform the longest prefix match and return the country code or "--"
    fn longest_prefix_match(&self, ip: &str) -> String {
        let mut longest_match = "";
        let mut country_code = "--".to_string();

        for entry in self.ipv4_table.iter().chain(self.ipv6_table.iter()) {
            if ip.starts_with(&entry.prefix) && entry.prefix.len() > longest_match.len() {
                longest_match = &entry.prefix;
                country_code = entry.country_code.clone();
            }
        }

        country_code
    }
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
                        Ok("".to_string()) // return empty string if the response isn't a valid country code
                    }
                }
                Err(_) => Ok("".to_string()), // return empty string if there's an error in parsing response
            }
        }
        Err(_) => Ok("".to_string()), // return empty string if there's an error in fetching data
    }
}

async fn get_country_code(ip: &str, source: IpSource) -> Result<String, reqwest::Error> {
   // sleep(Duration::from_millis(100)).await; // Introducing a 100ms delay, hopefully won't get blacklisted

    match source {
        IpSource::IpMap => get_country_code_from_ipmap(ip).await,
        IpSource::IpInfo => get_country_code_from_ipinfo(ip).await,
    }
}

fn main() {
    //geo-location
    let file_path = "/data/qlone/geolocation-db/geolocations_2023-03-29.csv";
    // Create a GeolocationLookup instance from the CSV file
    let geolocation_lookup = match GeolocationLookup::from_csv_file(file_path) {
        Ok(lookup) => lookup,
        Err(err) => {
            eprintln!("Error loading geolocation data: {:?}", err);
            std::process::exit(1); // Terminate the program with an error code
        }
    };

    let mut ixp_table = IpNetworkTable::new();

    let directory_path = "/data/qlone/topology-measurements/raw-traceroutes/";
    let output_directory_path = "/data/qlone/topology-measurements/ixps/";
    let ixp_data = "/data/qlone/topology-measurements/ixp-mappings/ix_caida_peeringdb.csv";

    // Iterate over each file in the directory
    let directory_entries = std::fs::read_dir(directory_path).expect("Failed to read directory");
    let table = build_network_table(
        "/data/qlone/topology-measurements/riswhois/riswhoisdump.IPv4",
        ixp_data,
    )
    .expect("Failed to build network table");

    //load ixp dataset
    load_ixp_prefixes_from_csv(ixp_data, &mut ixp_table).expect("Failed to load IXP prefixes");

    for entry_result in directory_entries {
        if let Ok(entry) = entry_result {
            let file_path = entry.path();
            if file_path.is_file() && file_path.extension() == Some(std::ffi::OsStr::new("json")) {
                println!("Processing file: {}", file_path.display());

                // Get the filename without the extension
                let file_stem = file_path
                    .file_stem()
                    .expect("Failed to get file stem")
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
                            let simplified_traceroute: SimplifiedTraceroute =
                                simplify_traceroute(traceroute);
                            //print_simplified_traceroute(simplified_traceroute, &table);
                            if let Err(err) = write_simplified_traceroute_to_json(
                                simplified_traceroute,
                                &table,
                                &output_file_path,
                                &ixp_table,
                                &geolocation_lookup,
                            ) {
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

fn is_ixp_inpath(traceroute: &SimplifiedTraceroute, ixp_table: &IpNetworkTable<String>) -> bool {
    for (_, from) in &traceroute.unique_pairs {
        let (converted_ip, _) = convert_to_ip_or_keep_string(from.as_deref());
        if let Some(ip) = converted_ip {
            if let Some((_network, _)) = ixp_table.longest_match(ip) {
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
        from_addr: atlas_traceroute.from,
        msm_id: atlas_traceroute.msm_id,
        prb_id: atlas_traceroute.prb_id,
        src_addr: atlas_traceroute.src_addr,
        timestamp: atlas_traceroute.timestamp,
        unique_pairs: unique_pairs_vec,
    }
}

fn build_network_table(
    file_path: &str,
    ixp_data: &str,
) -> Result<IpNetworkTable<String>, Box<dyn std::error::Error>> {
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
            if let (Some(origin_str), Some(prefix_str), Some(seen_by_str)) =
                (parts.next(), parts.next(), parts.next())
            {
                if let Ok(prefix) = prefix_str.parse::<IpNetwork>() {
                    if let Ok(seen_by) = seen_by_str.parse::<usize>() {
                        if seen_by < 10 {
                            continue; // Ignore entries where seen_by is less than 10
                        }
                    }
                    table.insert(prefix, origin_str.to_string());
                }
            }
        }
    }
    //Add IXP datasets to it as well
    let mut rdr = ReaderBuilder::new().from_path(ixp_data)?;

    for result in rdr.deserialize() {
        let record: IXP = result?;
        let prefix: IpNetwork = record.prefix_v4.parse()?;
        let ixp_name = record.name.clone();
        table.insert(prefix, ixp_name);
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
    ixp_table: &IpNetworkTable<String>,
    geolocation_lookup: &GeolocationLookup,
) -> Result<(), Box<dyn Error>> {
    // adding some debug code
    //  println!("{:?}", traceroute); // Print the traceroute value// Exit the program
    //process::exit(0);

    // Check if the traceroute contains any IXP prefix.
    if !is_ixp_inpath(&traceroute, ixp_table) {
        return Ok(());
    }

    //let dst_addr = traceroute.dst_addr.unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    //let from_addr = traceroute.from_addr;
    // let src_addr = traceroute.src_addr;
    // Assuming SimplifiedTraceroute structure definition as before
    let dst_addr = traceroute
        .dst_addr
        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    let from_addr = traceroute
        .from_addr
        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    let src_addr: Option<IpAddr> = traceroute.src_addr.and_then(|ip| Some(ip)).or(None);

    /* let from_addr = match traceroute.from_addr {
        Some(addr_str) => addr_str.parse::<IpAddr>().unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
        None => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), // Default value when None
    };
     */

    //let src_addr = traceroute.src_addr.unwrap_or_else(|| Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));

    // let src_addr = traceroute.src_addr.unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    let dst_addr_result = longest_match_lookup(Some(dst_addr), table);
    //let from_result = longest_match_lookup(from_addr, table);
    // let src_addr_result = longest_match_lookup(Some(src_addr), table);
    let src_addr_result = longest_match_lookup(src_addr, table);

    let mut hops = Vec::new();

    //geo-location
    let runtime = tokio::runtime::Runtime::new()?;
    //   let from_country = runtime.block_on(get_country_code(&from_addr.ok_or("Failed to get 'from' address")?.to_string(), IpSource::IpInfo))?;

    /*   let from_country = match from_addr {
        Some(from_addr) => geolocation_lookup.lookup_country_code(&from_addr),
        None => "--".to_string(),
    };

    let src_country = match src_addr {
        Some(src_addr) => geolocation_lookup.lookup_country_code(&src_addr),
        None => "--".to_string(),
    }; */

    let from_country =
        match runtime.block_on(get_country_code(&from_addr.to_string(), IpSource::IpMap)) {
            Ok(country) => country,
            Err(_) => "--".to_string(),
        };

    let src_country = match src_addr {
        Some(src_addr) => {
            match runtime.block_on(get_country_code(&src_addr.to_string(), IpSource::IpMap)) {
                Ok(country) => country,
                Err(_) => "--".to_string(),
            }
        }
        None => "--".to_string(),
    };

    let dst_country =
        match runtime.block_on(get_country_code(&dst_addr.to_string(), IpSource::IpMap)) {
            Ok(country) => country,
            Err(_) => "--".to_string(),
        };

    //let src_country = runtime.block_on(get_country_code(&src_addr.ok_or("Failed to get source address")?.to_string(), IpSource::IpInfo))?;

    for (hop, from) in &traceroute.unique_pairs {
        let (converted_ip, failed_conversion) = convert_to_ip_or_keep_string(from.as_deref());
        let mut hop_cc = "".to_string(); // Default value

        if let Some(ip) = converted_ip {
            let search_result = longest_match_lookup(Some(ip), table);
            //let ip_str = ip.to_string();
            let hop_cc = match converted_ip {
                Some(converted_ip) => {
                    match runtime.block_on(get_country_code(
                        &converted_ip.to_string(),
                        IpSource::IpMap,
                    )) {
                        Ok(country) => country,
                        Err(_) => "--".to_string(),
                    }
                }
                None => "--".to_string(),
            };

            /* if let Some(ip) = converted_ip {
                hop_cc = geolocation_lookup.lookup_country_code(&ip);

            } else {
                // Handle the case when `converted_ip` is `None`
                hop_cc = "--".to_string(); // Set a default value

            }
             */

            hops.push(json!({
                "hop_number": hop,
                "ip_addr": search_result.ip_addr,
                "prefix": search_result.network,
                "origin": search_result.origin,
                "hop_cc": hop_cc,
            }));
        }

        if let Some(failed_ip) = failed_conversion {
            hops.push(json!({
                "hop_number": hop,
                "ip_addr": failed_ip,
                "prefix": "",
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
            "prefix": dst_addr_result.network,
            "origin": dst_addr_result.origin,
            "dst_cc":dst_country
        },
        "from": {
            "from" : from_addr
       },
        "source": {
            "ip_addr": src_addr_result.ip_addr,
            "prefix": src_addr_result.network,
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
