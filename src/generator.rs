use chrono::{DateTime, Utc};
use regex::Regex;
use std::time::{SystemTime, UNIX_EPOCH};

// static REX_PATTERN: LazyCell<Regex> = LazyCell::new(|| {
//     let re = Regex::new(r"\n{2,}").unwrap();
//     re
// });

use crate::dns_structs::*;

pub fn generate(re: &Regex,options: &DnsZone, template: Option<&str>) -> String {
    let mut template = template.unwrap_or(DEFAULT_TEMPLATE).to_string();

    template = process_origin(options.origin.as_deref(), template);
    template = process_ttl(options.ttl, template);
    template = process_soa(options.soa.as_ref(), template);
    template = process_ns(options.ns.as_ref().unwrap_or(&vec![]), template);
    template = process_a(options.a.as_ref().unwrap_or(&vec![]), template);
    template = process_aaaa(options.aaaa.as_ref().unwrap_or(&vec![]), template);
    template = process_cname(options.cname.as_ref().unwrap_or(&vec![]), template);
    template = process_mx(options.mx.as_ref().unwrap_or(&vec![]), template);
    template = process_ptr(options.ptr.as_ref().unwrap_or(&vec![]), template);
    template = process_txt(options.txt.as_ref().unwrap_or(&vec![]), template);
    template = process_srv(options.srv.as_ref().unwrap_or(&vec![]), template);
    template = process_spf(options.spf.as_ref().unwrap_or(&vec![]), template);
    template = process_caa(options.caa.as_ref().unwrap_or(&vec![]), template);
    template = process_ds(options.ds.as_ref().unwrap_or(&vec![]), template);
    template = process_values(options, template);
    
    re.replace_all(&template, "\n\n").to_string()
}

fn process_origin(data: Option<&str>, template: String) -> String {
    let ret = if let Some(d) = data {
        format!("$ORIGIN {d}")
    } else {
        "".to_string()
    };
    template.replace("{$origin}", &ret)
}

fn process_ttl(data: Option<u32>, template: String) -> String {
    let ret = if let Some(d) = data {
        format!("$TTL {d}")
    } else {
        "".to_string()
    };
    template.replace("{$ttl}", &ret)
}

fn process_soa(data: Option<&Soa>, mut template: String) -> String {
    if let Some(soa) = data {
        let name = if soa.name.is_empty() { "@" } else { &soa.name };
        let ttl = soa.ttl.map_or("".to_string(), |t| t.to_string());
        template = template.replace("{name}", &format!("{}\t", name));
        template = template.replace("{ttl}", &format!("{}\t", ttl));
        template = template.replace("{mname}", &format!("{}\t", soa.mname));
        template = template.replace("{rname}", &format!("{}\t", soa.rname));
        template = template.replace("{serial}", &format!("{}\t", soa.serial));
        template = template.replace("{refresh}", &format!("{}\t", soa.refresh));
        template = template.replace("{retry}", &format!("{}\t", soa.retry));
        template = template.replace("{expire}", &format!("{}\t", soa.expire));
        template = template.replace("{minimum}", &format!("{}\t", soa.minimum));
    }
    template
}

fn process_ns(data: &[Ns], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!("{}\t{}IN\tNS\t{}\n", name, ttl, value.host)
        })
        .collect();
    template.replace("{ns}", &ret)
}

fn process_a(data: &[A], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!("{}\t{}IN\tA\t{}\n", name, ttl, value.ip)
        })
        .collect();
    template.replace("{a}", &ret)
}

fn process_aaaa(data: &[Aaaa], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!("{}\t{}IN\tAAAA\t{}\n", name, ttl, value.ip)
        })
        .collect();
    template.replace("{aaaa}", &ret)
}

fn process_cname(data: &[Cname], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!("{}\t{}IN\tCNAME\t{}\n", name, ttl, value.alias)
        })
        .collect();
    template.replace("{cname}", &ret)
}

fn process_mx(data: &[Mx], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!(
                "{}\t{}IN\tMX\t{}\t{}\n",
                name, ttl, value.preference, value.host
            )
        })
        .collect();
    template.replace("{mx}", &ret)
}

fn process_ptr(data: &[Ptr], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!("{}\t{}IN\tPTR\t{}\n", name, ttl, value.host)
        })
        .collect();
    template.replace("{ptr}", &ret)
}

fn process_txt(data: &[Txt], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!("{}\t{}IN\tTXT\t{}\n", name, ttl, value.txt)
        })
        .collect();
    template.replace("{txt}", &ret)
}

fn process_srv(data: &[Srv], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!(
                "{}\t{}IN\tSRV\t{}\t{}\t{}\t{}\n",
                name, ttl, value.priority, value.weight, value.port, value.target
            )
        })
        .collect();
    template.replace("{srv}", &ret)
}

fn process_spf(data: &[Spf], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!("{}\t{}IN\tSPF\t{}\n", name, ttl, value.data)
        })
        .collect();
    template.replace("{spf}", &ret)
}

fn process_caa(data: &[Caa], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!(
                "{}\t{}IN\tCAA\t{}\t{}\t{}\n",
                name, ttl, value.flags, value.tag, value.value
            )
        })
        .collect();
    template.replace("{caa}", &ret)
}

fn process_ds(data: &[Ds], template: String) -> String {
    let ret: String = data
        .iter()
        .map(|value| {
            let name = if value.name.is_empty() { "@" } else { &value.name };
            let ttl = value.ttl.map_or("".to_string(), |t| format!("{}\t", t));
            format!(
                "{}\t{}IN\tDS\t{}\t{}\t{}\t{}\n",
                name, ttl, value.key_tag, value.algorithm, value.digest_type, value.digest
            )
        })
        .collect();
    template.replace("{ds}", &ret)
}

fn process_values(options: &DnsZone, template: String) -> String {
    let zone = options.origin.as_deref().unwrap_or_else(|| {
        options.soa.as_ref().map_or("", |s| &s.name)
    });

    let now: DateTime<Utc> = Utc::now();
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    template
        .replace("{zone}", zone)
        .replace("{datetime}", &now.to_rfc3339())
        .replace("{time}", &time.to_string())
}
