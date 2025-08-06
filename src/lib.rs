mod dns_structs;
mod generator;
mod parser;

pub use dns_structs::*;
use regex::Regex;

struct ContextRegex {
    parser: Regex,
    parser_soa: Regex,
    generator: Regex
}

pub struct DnsZonefile {
    ctx: ContextRegex
}

/// DnsZonefile
///
impl DnsZonefile {
    /// generate Zonefile from DnsZone struct
    pub fn generate(&self, dns_zone: &DnsZone, template: Option<&str>) -> String {
        generator::generate(&self.ctx.generator, dns_zone, template)
    }
    /// parse data from zonfile to DnsZone struct then can convert into json
    /// return error for empty zone data rather then all none!
    pub fn parse(&self, data: &str) -> Result<DnsZone, String> {
        parser::parse(&self.ctx.parser, &self.ctx.parser_soa, data)
    }
}

impl Default for DnsZonefile {
    fn default() -> Self {
        let parser = Regex::new(r"\s+").unwrap();
        let generator = Regex::new(r"\n{2,}").expect("valid pattern");
        let parser_soa = Regex::new(r"(?is)(SOA\s+.*?\s*\([\s\S]*?\))").expect("valid pattern");
        Self { ctx: ContextRegex { parser, parser_soa, generator } }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn get_forward_zone_json() -> DnsZone {
        let json_str = fs::read_to_string("tests/zonefile_forward.json")
            .expect("Failed to read zonefile_forward.json");
        serde_json::from_str(&json_str).expect("Failed to parse zonefile_forward.json")
    }

    #[test]
    fn test_generate_global_info() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("$ORIGIN MYDOMAIN.COM."));
        assert!(generated.contains("$TTL 3600"));
    }

    #[test]
    fn test_generate_soa_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("IN\tSOA\tNS1.NAMESERVER.NET.\tHOSTMASTER.MYDOMAIN.COM."));
        assert!(generated.contains("1406291485\t ;serial"));
        assert!(generated.contains("3600\t ;refresh"));
    }

    #[test]
    fn test_generate_ns_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("@\tIN\tNS\tNS1.NAMESERVER.NET."));
        assert!(generated.contains("@\tIN\tNS\tNS2.NAMESERVER.NET."));
    }

    #[test]
    fn test_generate_mx_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("@\tIN\tMX\t0\tmail1"));
        assert!(generated.contains("@\tIN\tMX\t10\tmail2"));
    }

    #[test]
    fn test_generate_a_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("@\tIN\tA\t2.2.2.2"));
        assert!(generated.contains("@\tIN\tA\t1.1.1.1"));
        assert!(generated.contains("@\tIN\tA\t127.0.0.1"));
        assert!(generated.contains("www\tIN\tA\t127.0.0.1"));
        assert!(generated.contains("mail\tIN\tA\t127.0.0.1"));
        assert!(generated.contains("mail\tIN\tA\t1.2.3.4"));
        assert!(generated.contains("tst\t300\tIN\tA\t101.228.10.127"));
    }

    #[test]
    fn test_generate_aaaa_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("@\tIN\tAAAA\t::1"));
        assert!(generated.contains("mail\tIN\tAAAA\t2001:db8::1"));
        assert!(generated.contains("A\t200\tIN\tAAAA\t2001:db8::1"));
    }
    
    #[test]
    fn test_generate_cname_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("mail1\tIN\tCNAME\tmail"));
        assert!(generated.contains("mail2\tIN\tCNAME\tmail"));
        assert!(generated.contains("CNAME\tIN\tCNAME\tCNAME"));
    }

    #[test]
    fn test_generate_txt_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains(r#"treefrog.ca.	IN	TXT	"v=spf1 a mx a:mail.treefrog.ca a:webmail.treefrog.ca ip4:76.75.250.33 ?all" "asdfsdaf" "sdfsadfdasf""#));
        assert!(generated.contains(r#"treemonkey.ca.	IN	TXT	"v=DKIM1\; k=rsa\; p=MIGf...""#));
    }
    
    #[test]
    fn test_generate_srv_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("_foobar._tcp\t200\tIN\tSRV\t0\t1\t9\told-slow-box.example.com."));
        assert!(generated.contains("_foobar._tcp\tIN\tSRV\t0\t3\t9\tnew-fast-box.example.com."));
        assert!(generated.contains("_foobar._tcp\tIN\tSRV\t1\t0\t9\tsysadmins-box.example.com."));
        assert!(generated.contains("_foobar._tcp\tIN\tSRV\t1\t0\t9\tserver.example.com."));
        assert!(generated.contains("*._tcp\tIN\tSRV\t0\t0\t0\t."));
        assert!(generated.contains("*._udp\tIN\tSRV\t0\t0\t0\t."));
    }

    #[test]
    fn test_generate_spf_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains(r#"test	IN	SPF	"v=spf1" "mx:gcloud-node.com." "-all""#));
        assert!(generated.contains(r#"test1	IN	SPF	"v=spf2" "mx:gcloud-node.com." "-all""#));
    }

    #[test]
    fn test_generate_caa_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains(r#"@	IN	CAA	0	issue	"ca.example.net; account=230123""#));
        assert!(generated.contains(r#"@	IN	CAA	0	iodef	"mailto:security@example.com""#));
        assert!(generated.contains(r#"@	IN	CAA	0	iodef	"http://iodef.example.com/""#));
    }

    #[test]
    fn test_generate_ds_records() {
        let json = get_forward_zone_json();
        let generated = generate(&json, None);
        assert!(generated.contains("secure.example.\tIN\tDS\ttag=12345\talg=3\tdigest_type=1\t<foofoo>"));
        assert!(generated.contains(r#"secure.example.	IN	DS	tag=12345	alg=3	digest_type=1	"<foofoo>""#));
    }


     fn get_parsed_forward_zone() -> DnsZone {
        let text = fs::read_to_string("tests/zonefile_forward.txt")
            .expect("Failed to read zonefile_forward.txt");
        parse(&text)
    }

    fn get_expected_forward_zone_json() -> DnsZone {
        let json_str = fs::read_to_string("tests/zonefile_forward.json")
            .expect("Failed to read zonefile_forward.json");
        serde_json::from_str(&json_str).expect("Failed to parse zonefile_forward.json")
    }
    
    #[test]
    fn test_generate_forward_zone() {
        let json_data = get_expected_forward_zone_json();
        let generated_text = generate(&json_data, None);
        
        assert!(generated_text.contains("$ORIGIN MYDOMAIN.COM."));
        assert!(generated_text.contains("IN\tSOA\tNS1.NAMESERVER.NET."));
        assert!(generated_text.contains("tst\t300\tIN\tA\t101.228.10.127"));
    }

    // ----- Parse Tests -----
    #[test]
    fn test_parse_global_info() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.origin, expected.origin);
        assert_eq!(parsed.ttl, expected.ttl);
    }

    #[test]
    fn test_parse_soa_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.soa, expected.soa);
    }
    
    #[test]
    fn test_parse_ns_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.ns, expected.ns);
    }

    #[test]
    fn test_parse_mx_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.mx, expected.mx);
    }

    #[test]
    fn test_parse_a_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.a, expected.a);
    }

    #[test]
    fn test_parse_aaaa_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.aaaa, expected.aaaa);
    }

    #[test]
    fn test_parse_cname_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.cname, expected.cname);
    }
    
    #[test]
    fn test_parse_txt_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.txt, expected.txt);
    }

    #[test]
    fn test_parse_srv_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.srv, expected.srv);
    }

    #[test]
    fn test_parse_spf_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.spf, expected.spf);
    }

    #[test]
    fn test_parse_caa_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.caa, expected.caa);
    }

    #[test]
    fn test_parse_ds_records() {
        let parsed = get_parsed_forward_zone();
        let expected = get_expected_forward_zone_json();
        assert_eq!(parsed.ds, expected.ds);
    }

    // ----- Idempotence Test -----
    
    #[test]
    fn test_forward_idempotence() {
        // 1. Start with the text file
        let original_text = fs::read_to_string("tests/zonefile_forward.txt")
            .expect("Failed to read zonefile_forward.txt");

        // 2. Parse it to a JSON object (struct)
        let json1 = parse(&original_text);

        // 3. Generate it back to text
        let generated_text = generate(&json1, None);

        // 4. Parse the generated text back to a JSON object (struct)
        let json2 = parse(&generated_text);

        // 5. The two JSON objects should be deeply equal
        assert_eq!(json1, json2, "Parsed objects should be equal after a generate/parse cycle.");
    }
}
