use crate::dns_structs::*;
use regex::Regex;

#[derive(Debug)]
pub struct NormalizedRR {
    rr_type: String,
    tokens: Vec<String>,
    has_name: bool,
    has_ttl: bool,
    type_index: usize,
}

fn get_name(
    rr_data: &NormalizedRR,
    records_so_far: &[impl GetName],
) -> String {
    if rr_data.has_name {
        rr_data.tokens[0].clone()
    } else {
        records_so_far.last().map_or("@".to_string(), |r| r.get_name().to_string())
    }
}

trait GetName {
    fn get_name(&self) -> &str;
}
impl GetName for Ns { fn get_name(&self) -> &str { &self.name } }
impl GetName for A { fn get_name(&self) -> &str { &self.name } }
impl GetName for Aaaa { fn get_name(&self) -> &str { &self.name } }
impl GetName for Cname { fn get_name(&self) -> &str { &self.name } }
impl GetName for Mx { fn get_name(&self) -> &str { &self.name } }
impl GetName for Txt { fn get_name(&self) -> &str { &self.name } }
impl GetName for Ptr { fn get_name(&self) -> &str { &self.name } }
impl GetName for Srv { fn get_name(&self) -> &str { &self.name } }
impl GetName for Spf { fn get_name(&self) -> &str { &self.name } }
impl GetName for Caa { fn get_name(&self) -> &str { &self.name } }
impl GetName for Ds { fn get_name(&self) -> &str { &self.name } }

fn parse_soa(rr_tokens: &[&str]) -> Soa {
    let l = rr_tokens.len();
    Soa {
        name: rr_tokens[0].to_string(),
        mname: rr_tokens[l - 7].to_string(),
        rname: rr_tokens[l - 6].to_string(),
        serial: rr_tokens[l - 5].parse().unwrap_or(0),
        refresh: rr_tokens[l - 4].parse().unwrap_or(0),
        retry: rr_tokens[l - 3].parse().unwrap_or(0),
        expire: rr_tokens[l - 2].parse().unwrap_or(0),
        minimum: rr_tokens[l - 1].parse().unwrap_or(0),
        ttl: rr_tokens.get(1).and_then(|t| t.parse().ok()),
    }
}

fn parse_ns(rr_data: &NormalizedRR, records_so_far: &[Ns]) -> Ns {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    Ns {
        name,
        host: rr_data.tokens[l - 1].to_string(),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_a(rr_data: &NormalizedRR, records_so_far: &[A]) -> A {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    A {
        name,
        ip: rr_data.tokens[l - 1].to_string(),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_aaaa(rr_data: &NormalizedRR, records_so_far: &[Aaaa]) -> Aaaa {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    Aaaa {
        name,
        ip: rr_data.tokens[l - 1].to_string(),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_cname(rr_data: &NormalizedRR, records_so_far: &[Cname]) -> Cname {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    Cname {
        name,
        alias: rr_data.tokens[l - 1].to_string(),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_mx(rr_data: &NormalizedRR, records_so_far: &[Mx]) -> Mx {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    Mx {
        name,
        preference: rr_data.tokens[l - 2].parse().unwrap_or(0),
        host: rr_data.tokens[l - 1].to_string(),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_txt(rr_data: &NormalizedRR, records_so_far: &[Txt]) -> Txt {
    let name = get_name(rr_data, records_so_far);
    let txt_array = &rr_data.tokens[rr_data.type_index + 1..];
    Txt {
        name,
        txt: txt_array.join(" "),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_ptr(rr_data: &NormalizedRR, records_so_far: &[Ptr], current_origin: &str) -> Ptr {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    Ptr {
        fullname: format!("{}.{}", name, current_origin),
        name,
        host: rr_data.tokens[l - 1].to_string(),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_srv(rr_data: &NormalizedRR, records_so_far: &[Srv]) -> Srv {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    Srv {
        name,
        target: rr_data.tokens[l - 1].to_string(),
        priority: rr_data.tokens[l - 4].parse().unwrap_or(0),
        weight: rr_data.tokens[l - 3].parse().unwrap_or(0),
        port: rr_data.tokens[l - 2].parse().unwrap_or(0),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_spf(rr_data: &NormalizedRR, records_so_far: &[Spf]) -> Spf {
    let name = get_name(rr_data, records_so_far);
    let data_array = &rr_data.tokens[rr_data.type_index + 1..];
    Spf {
        name,
        data: data_array.join(" "),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_caa(rr_data: &NormalizedRR, records_so_far: &[Caa]) -> Caa {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    Caa {
        name,
        flags: rr_data.tokens[l - 3].parse().unwrap_or(0),
        tag: rr_data.tokens[l - 2].to_string(),
        value: rr_data.tokens[l - 1].to_string(),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn parse_ds(rr_data: &NormalizedRR, records_so_far: &[Ds]) -> Ds {
    let name = get_name(rr_data, records_so_far);
    let l = rr_data.tokens.len();
    Ds {
        name,
        key_tag: rr_data.tokens[l-4].to_string(),
        algorithm: rr_data.tokens[l-3].to_string(),
        digest_type: rr_data.tokens[l-2].to_string(),
        digest: rr_data.tokens[l - 1].to_string(),
        ttl: if rr_data.has_ttl { rr_data.tokens[1].parse().ok() } else { None },
    }
}

fn flatten_soa(re: &Regex, re_whitespace: &Regex, text: &str) -> String {
    if let Some(captures) = re.captures(text) {
        let soa_block = &captures[1];

        let flattened_soa = re_whitespace.replace_all(soa_block, " ");
        let flattened_soa = flattened_soa.replace(&['(', ')'][..], " ");

        // Reconstruct the text with the flattened SOA record
        return text.replace(soa_block, &flattened_soa);
    }

    text.to_string()
}

fn split_args(input: &str, sep: Option<char>, keep_quotes: bool) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_token = String::new();
    let mut in_double_quotes = false;
    let mut in_single_quotes = false;

    for c in input.chars() {
        if c == '"' && !in_single_quotes {
            in_double_quotes = !in_double_quotes;
            if keep_quotes {
                current_token.push(c);
            }
            continue;
        }
        if c == '\'' && !in_double_quotes {
            in_single_quotes = !in_single_quotes;
            if keep_quotes {
                current_token.push(c);
            }
            continue;
        }

        let is_separator = match sep {
            Some(s) => c == s,
            None => c.is_whitespace(),
        };

        if is_separator && !in_double_quotes && !in_single_quotes {
            if !current_token.is_empty() {
                result.push(current_token);
                current_token = String::new();
            }
        } else {
            current_token.push(c);
        }
    }

    if !current_token.is_empty() {
        result.push(current_token);
    } else if sep.is_some() && input.ends_with(sep.unwrap()) {
        // Handle case where line ends with a separator, e.g., in `remove_comments`
        result.push("".to_string());
    }

    // For whitespace separation, filter out empty strings that result from multiple spaces.
    if sep.is_none() {
        result.into_iter().filter(|s| !s.is_empty()).collect()
    } else {
        result
    }
}

fn remove_comments(text: &str) -> String {
    let mut result = String::new();
    for line in text.lines() {
        if line.trim().starts_with(';') {
            continue;
        }

        // Split by semicolon to find comments, keeping quotes.
        let tokens = split_args(line, Some(';'), true);

        let mut first_part = String::new();
        for (i, token) in tokens.iter().enumerate() {
            first_part.push_str(token);
            if i < tokens.len() - 1 { // If not the last token
                if token.ends_with('\\') {
                    // This was an escaped semicolon, so re-add it.
                    first_part.pop(); // remove backslash
                    first_part.push(';');
                } else {
                    // This was a real comment, so stop processing this line.
                    break;
                }
            }
        }
        result.push_str(&first_part);
        result.push('\n');
    }
    result
}

fn normalize_rr(rr: &str) -> NormalizedRR {
    let rr_tokens: Vec<String> = split_args(rr, None, true);

    let has_name = !rr.starts_with(char::is_whitespace) && !rr.is_empty();

    let ttl_index = if has_name { 1 } else { 0 };
    let has_ttl = rr_tokens.get(ttl_index).and_then(|t| t.parse::<u32>().ok()).is_some();

    let mut type_index = if has_name { 1 } else { 0 };
    if has_ttl {
        type_index += 1;
    }

    // Adjust for 'IN' class
    if rr_tokens.get(type_index).is_some_and(|s| s == "IN") {
        type_index += 1;
    }

    let rr_type = rr_tokens.get(type_index).cloned().unwrap_or_default();

    NormalizedRR {
        rr_type,
        tokens: rr_tokens,
        has_name,
        has_ttl,
        type_index,
    }
}

fn parse_rrs(text: &str) -> DnsZone {
    let mut zone = DnsZone::default();
    let rrs = text.lines();

    for rr in rrs {
        if rr.trim().is_empty() {
            continue;
        }

        let rr_array = split_args(rr, None, true);
        if rr.starts_with("$ORIGIN") {
            zone.origin = rr_array.get(1).map(|s| s.to_string());
        } else if rr.starts_with("$TTL") {
            zone.ttl = rr_array.get(1).and_then(|s| s.parse().ok());
        } else {
            let nrr = normalize_rr(rr);
            let nrr_tokens: Vec<&str> = rr.split_whitespace().collect();

            match nrr.rr_type.as_str() {
                "SOA" => zone.soa = Some(parse_soa(&nrr_tokens)),
                "NS" => {
                    let records = zone.ns.get_or_insert_with(Vec::new);
                    records.push(parse_ns(&nrr, records));
                },
                "A" => {
                    let records = zone.a.get_or_insert_with(Vec::new);
                    records.push(parse_a(&nrr, records));
                },
                "AAAA" => {
                    let records = zone.aaaa.get_or_insert_with(Vec::new);
                    records.push(parse_aaaa(&nrr, records));
                },
                "CNAME" => {
                    let records = zone.cname.get_or_insert_with(Vec::new);
                    records.push(parse_cname(&nrr, records));
                },
                "MX" => {
                    let records = zone.mx.get_or_insert_with(Vec::new);
                    records.push(parse_mx(&nrr, records));
                },
                 "TXT" => {
                    let records = zone.txt.get_or_insert_with(Vec::new);
                    records.push(parse_txt(&nrr, records));
                },
                "PTR" => {
                    let records = zone.ptr.get_or_insert_with(Vec::new);
                    let origin = zone.origin.as_deref().unwrap_or("");
                    records.push(parse_ptr(&nrr, records, origin));
                },
                "SRV" => {
                    let records = zone.srv.get_or_insert_with(Vec::new);
                    records.push(parse_srv(&nrr, records));
                },
                "SPF" => {
                    let records = zone.spf.get_or_insert_with(Vec::new);
                    records.push(parse_spf(&nrr, records));
                },
                "CAA" => {
                    let records = zone.caa.get_or_insert_with(Vec::new);
                    records.push(parse_caa(&nrr, records));
                },
                "DS" => {
                    let records = zone.ds.get_or_insert_with(Vec::new);
                    records.push(parse_ds(&nrr, records));
                },
                _ => { /* Unknown record type, do nothing */ }
            }
        }
    }
    zone
}

pub fn parse(re_ws: &Regex, re_soa: &Regex,text: &str) -> Result<DnsZone, String> {
    let without_comments = remove_comments(text);
    let flattened = flatten_soa(re_soa, re_ws, &without_comments);
    let dns_zone = parse_rrs(&flattened);
    if dns_zone.is_empty() {
        return Err("Invalid DNS Zonefile".to_owned());
    }
    Ok(dns_zone)
}
