use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
//use crate::utils::empty_string_as_none;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AtlasTraceroute {
    pub af: u8,
    pub dst_addr: Option<IpAddr>,
    pub dst_name: String,
    pub endtime: DateTime<Utc>,
    pub from: Option<String>,
    pub msm_id: u64,
    pub msm_name: String,
    pub paris_id: u16,
    pub prb_id: u64,
    pub proto: String,
    pub result: Vec<AtlasTracerouteHop>,
    pub size: u16,
    pub src_addr: Option<IpAddr>,
    pub timestamp: DateTime<Utc>,
    pub kind: String,
}



#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AtlasTracerouteHop {
    pub hop: u8,
    pub result: Vec<AtlasTracerouteReply>,
}


#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AtlasTracerouteReply {
    pub from: Option<String>,
    pub rtt: Option<f64>,
    pub size: Option<u16>,
    pub ttl: Option<u8>,
    pub icmpext: Option<Vec<AtlasIcmpExt>>,
}


#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AtlasIcmpExt {
    pub version: u8,
    pub rfc4884: u8,
    pub obj: Vec<AtlasIcmpExtObj>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AtlasIcmpExtObj {
    pub class: u8,
    pub kind: u8,
    pub mpls: Vec<AtlasIcmpExtMplsData>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AtlasIcmpExtMplsData {
    pub label: u32,
    pub exp: u8,
    pub s: u8,
    pub ttl: u8,
}

impl From<json_parser::formats::atlas::AtlasTraceroute> for AtlasTraceroute {
    fn from(atlas_traceroute: json_parser::formats::atlas::AtlasTraceroute) -> Self {
        AtlasTraceroute {
            af: atlas_traceroute.af,
            dst_addr: atlas_traceroute.dst_addr,
            dst_name: atlas_traceroute.dst_name,
            endtime: atlas_traceroute.endtime,
            from: atlas_traceroute.from,
            msm_id: atlas_traceroute.msm_id,
            msm_name: atlas_traceroute.msm_name,
            paris_id: atlas_traceroute.paris_id,
            prb_id: atlas_traceroute.prb_id,
            proto: atlas_traceroute.proto,
            result: atlas_traceroute.result.into_iter().map(|hop| {
                AtlasTracerouteHop {
                    hop: hop.hop,
                    result: hop.result.into_iter().map(|reply| {
                        if reply.from.is_none() {
                            AtlasTracerouteReply {
                                from: Some("*".to_string()),
                                rtt: None,
                                size: None,
                                ttl: None,
                                icmpext: None,
                            }
                        } else {
                            AtlasTracerouteReply {
                                from: reply.from,
                                rtt: Some(reply.rtt),
                                size: Some(reply.size),
                                ttl: Some(reply.ttl),
                                icmpext: Some(reply.icmpext.into_iter().map(|icmpext| {
                                    AtlasIcmpExt {
                                        version: icmpext.version,
                                        rfc4884: icmpext.rfc4884,
                                        obj: icmpext.obj.into_iter().map(|obj| {
                                            AtlasIcmpExtObj {
                                                class: obj.class,
                                                kind: obj.kind,
                                                mpls: obj.mpls.into_iter().map(|mpls| {
                                                    AtlasIcmpExtMplsData {
                                                        label: mpls.label,
                                                        exp: mpls.exp,
                                                        s: mpls.s,
                                                        ttl: mpls.ttl,
                                                    }
                                                }).collect(),
                                            }
                                        }).collect(),
                                    }
                                }).collect()),
                            }
                        }
                    }).collect(),
                }
            }).collect(),
            size: atlas_traceroute.size,
            src_addr: atlas_traceroute.src_addr,
            timestamp: atlas_traceroute.timestamp,
            kind: atlas_traceroute.kind,
        }
    }
}

