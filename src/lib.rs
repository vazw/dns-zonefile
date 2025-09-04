mod dns_structs;
mod generator;
mod parser;

pub use dns_structs::*;
use regex::Regex;

#[derive(Debug, Clone)]
struct ContextRegex {
    parser: Regex,
    parser_soa: Regex,
    generator: Regex
}

#[derive(Debug, Clone)]
pub struct DnsZonefile {
    ctx: ContextRegex
}

/// DnsZonefile
/// This is main struct 
/// an interface to generate and parse function
/// which will create Regex resource once using `DnsZonefile::default()`
/// if you want to use with serde enable feature `serde`
/// there is also `paperclip` feature use to expose the struct to openapi specs
/// ```rust
/// use dns_zonefile::{DnsRecord, DnsZonefile};
///
/// let dns = DnsZonefile::default();
/// let zonefile_example = r#"
/// $ORIGIN MYDOMAIN.COM.
/// $TTL 3600
/// @    IN    SOA    NS1.NAMESERVER.NET.    HOSTMASTER.MYDOMAIN.COM.    (
///             1406291485     ;serial
///             3600     ;refresh
///             600     ;retry
///             604800     ;expire
///             86400     ;minimum ttl
/// )
/// 
/// @    NS    NS1.NAMESERVER.NET.
/// @    NS    NS2.NAMESERVER.NET.
/// 
///     IN  A    2.2.2.2
///     A    1.1.1.1
/// @    A    127.0.0.1
/// www    A    127.0.0.1
/// mail    A    127.0.0.1
///             A 1.2.3.4
/// tst 300 IN A 101.228.10.127;this is a comment
/// 
/// @    AAAA    ::1
/// mail    AAAA    2001:db8::1
/// A  200 AAAA  2001:db8::1
/// "#;
/// 
/// let Ok(zone_data) = dns.parse(zonefile_example) else { return;};
/// println!("{}", serde_json::to_string_pretty(&zone_data).unwrap());
/// 
/// let zonefile = dns.generate(&zone_data, None);
/// println!("{zonefile}");
/// ```
impl DnsZonefile {
    /// generate Zonefile string from DnsRecord data struct like so
    /// 
    pub fn generate(&self, dns_zone: &DnsRecord, template: Option<&str>) -> String {
        generator::generate(&self.ctx.generator, dns_zone, template)
    }
    /// parse data from zonfile to DnsRecord struct
    ///
    /// then can convert into json later using serde
    ///
    /// THIS function **return** error for empty zone data rather then all none!
    pub fn parse(&self, data: &str) -> Result<DnsRecord, String> {
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
    use super::{DnsZonefile, DnsRecord};
    use std::fs;

    fn get_forward_zone_json() -> DnsRecord {
        let json_str = fs::read_to_string("tests/zonefile_forward.json")
            .expect("Failed to read zonefile_forward.json");
        serde_json::from_str(&json_str).expect("Failed to parse zonefile_forward.json")
    }

    #[test]
    fn test_generate_global_info() {
        let dns_zonefile = DnsZonefile::default();
        let json = get_forward_zone_json();
        let generated = dns_zonefile.generate(&json, None);
        assert!(generated.contains("$ORIGIN MYDOMAIN.COM."));
        assert!(generated.contains("$TTL 3600"));
        assert!(generated.contains("IN\tSOA\tNS1.NAMESERVER.NET.\tHOSTMASTER.MYDOMAIN.COM."));
        assert!(generated.contains("1406291485\t ;serial"));
        assert!(generated.contains("3600\t ;refresh"));
        assert!(generated.contains("@\tIN\tNS\tNS1.NAMESERVER.NET."));
        assert!(generated.contains("@\tIN\tNS\tNS2.NAMESERVER.NET."));
        assert!(generated.contains("@\tIN\tMX\t0\tmail1"));
        assert!(generated.contains("@\tIN\tMX\t10\tmail2"));
        assert!(generated.contains("@\tIN\tA\t2.2.2.2"));
        assert!(generated.contains("@\tIN\tA\t1.1.1.1"));
        assert!(generated.contains("@\tIN\tA\t127.0.0.1"));
        assert!(generated.contains("www\tIN\tA\t127.0.0.1"));
        assert!(generated.contains("mail\tIN\tA\t127.0.0.1"));
        assert!(generated.contains("mail\tIN\tA\t1.2.3.4"));
        assert!(generated.contains("tst\t300\tIN\tA\t101.228.10.127"));
        assert!(generated.contains("@\tIN\tAAAA\t::1"));
        assert!(generated.contains("mail\tIN\tAAAA\t2001:db8::1"));
        assert!(generated.contains("A\t200\tIN\tAAAA\t2001:db8::1"));
        assert!(generated.contains("mail1\tIN\tCNAME\tmail"));
        assert!(generated.contains("mail2\tIN\tCNAME\tmail"));
        assert!(generated.contains("CNAME\tIN\tCNAME\tCNAME"));
        assert!(generated.contains(r#"treefrog.ca.	IN	TXT	"v=spf1 a mx a:mail.treefrog.ca a:webmail.treefrog.ca ip4:76.75.250.33 ?all" "asdfsdaf" "sdfsadfdasf""#));
        assert!(generated.contains(r#"treemonkey.ca.	IN	TXT	"v=DKIM1\; k=rsa\; p=MIGf...""#));
        assert!(generated.contains("_foobar._tcp\t200\tIN\tSRV\t0\t1\t9\told-slow-box.example.com."));
        assert!(generated.contains("_foobar._tcp\tIN\tSRV\t0\t3\t9\tnew-fast-box.example.com."));
        assert!(generated.contains("_foobar._tcp\tIN\tSRV\t1\t0\t9\tsysadmins-box.example.com."));
        assert!(generated.contains("_foobar._tcp\tIN\tSRV\t1\t0\t9\tserver.example.com."));
        assert!(generated.contains("*._tcp\tIN\tSRV\t0\t0\t0\t."));
        assert!(generated.contains("*._udp\tIN\tSRV\t0\t0\t0\t."));
        assert!(generated.contains(r#"test	IN	SPF	"v=spf1" "mx:gcloud-node.com." "-all""#));
        assert!(generated.contains(r#"test1	IN	SPF	"v=spf2" "mx:gcloud-node.com." "-all""#));
        assert!(generated.contains(r#"@	IN	CAA	0	issue	"ca.example.net; account=230123""#));
        assert!(generated.contains(r#"@	IN	CAA	0	iodef	"mailto:security@example.com""#));
        assert!(generated.contains(r#"@	IN	CAA	0	iodef	"http://iodef.example.com/""#));
        assert!(generated.contains("secure.example.\tIN\tDS\ttag=12345\talg=3\tdigest_type=1\t<foofoo>"));
        assert!(generated.contains(r#"secure.example.	IN	DS	tag=12345	alg=3	digest_type=1	"<foofoo>""#));
    }


     fn get_parsed_forward_zone() -> DnsRecord {
        let text = fs::read_to_string("tests/zonefile_forward.txt")
            .expect("Failed to read zonefile_forward.txt");
        let dns_zonefile = DnsZonefile::default();
        dns_zonefile.parse(&text).unwrap()
    }

    fn get_expected_forward_zone_json() -> DnsRecord {
        let json_str = fs::read_to_string("tests/zonefile_forward.json")
            .expect("Failed to read zonefile_forward.json");
        serde_json::from_str(&json_str).expect("Failed to parse zonefile_forward.json")
    }
    
    #[test]
    fn test_generate_forward_zone() {
        let json_data = get_expected_forward_zone_json();
        let dns_zonefile = DnsZonefile::default();
        let generated_text = dns_zonefile.generate(&json_data, None);
        
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
        assert_eq!(parsed.soa, expected.soa);
        assert_eq!(parsed.ns, expected.ns);
        assert_eq!(parsed.mx, expected.mx);
        assert_eq!(parsed.a, expected.a);
        assert_eq!(parsed.aaaa, expected.aaaa);
        assert_eq!(parsed.cname, expected.cname);
        assert_eq!(parsed.txt, expected.txt);
        assert_eq!(parsed.srv, expected.srv);
        assert_eq!(parsed.spf, expected.spf);
        assert_eq!(parsed.caa, expected.caa);
        assert_eq!(parsed.ds, expected.ds);
    }

    // ----- Idempotence Test -----
    
    #[test]
    fn test_forward_idempotence() {
        // 1. Start with the text file
        let original_text = fs::read_to_string("tests/zonefile_forward.txt")
            .expect("Failed to read zonefile_forward.txt");
        let dns_zonefile = DnsZonefile::default();

        // 2. Parse it to a JSON object (struct)
        let json1 = dns_zonefile.parse(&original_text).expect("correct!");

        // 3. Generate it back to text
        let generated_text = dns_zonefile.generate(&json1, None);

        // 4. Parse the generated text back to a JSON object (struct)
        let json2 = dns_zonefile.parse(&generated_text).expect("json");

        // 5. The two JSON objects should be deeply equal
        assert_eq!(json1, json2, "Parsed objects should be equal after a generate/parse cycle.");
    }

    #[test]
    fn test_empty_struct() {
        let dns_record = DnsRecord::default();
        assert_eq!(dns_record.is_empty(), true);
    }
}
