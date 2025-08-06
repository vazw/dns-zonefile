use serde::{Serialize,Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Soa {
    pub name: String,
    pub minimum: u32,
    pub expire: u32,
    pub retry: u32,
    pub refresh: u32,
    pub serial: u32,
    pub rname: String,
    pub mname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Ns {
    pub name: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct A {
    pub name: String,
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Aaaa {
    pub name: String,
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Cname {
    pub name: String,
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Mx {
    pub name: String,
    pub preference: u16,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Txt {
    pub name: String,
    pub txt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Ptr {
    pub name: String,
    pub fullname: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Srv {
    pub name: String,
    pub target: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Spf {
    pub name: String,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Caa {
    pub name: String,
    pub flags: u8,
    pub tag: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Ds {
    pub name: String,
    pub key_tag: String,
    pub algorithm: String,
    pub digest_type: String,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsZone {
    #[serde(rename = "$origin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "$ttl")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soa: Option<Soa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ns: Option<Vec<Ns>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a: Option<Vec<A>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaaa: Option<Vec<Aaaa>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<Vec<Cname>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mx: Option<Vec<Mx>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txt: Option<Vec<Txt>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<Vec<Ptr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srv: Option<Vec<Srv>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spf: Option<Vec<Spf>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caa: Option<Vec<Caa>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds: Option<Vec<Ds>>,
}

pub const DEFAULT_TEMPLATE: &str = r#"; Zone: {zone}
; Exported  (yyyy-mm-ddThh:mm:ss.sssZ): {datetime}

{$origin}
{$ttl}

; SOA Record
{name} {ttl}	IN	SOA	{mname}{rname}(
{serial} ;serial
{refresh} ;refresh
{retry} ;retry
{expire} ;expire
{minimum} ;minimum ttl
)

; NS Records
{ns}

; MX Records
{mx}

; A Records
{a}

; AAAA Records
{aaaa}

; CNAME Records
{cname}

; PTR Records
{ptr}

; TXT Records
{txt}

; SRV Records
{srv}

; SPF Records
{spf}

; CAA Records
{caa}

; DS Records
{ds}

"#;
