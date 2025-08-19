#[cfg(feature="serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature="paperclip")]
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Soa {
    pub name: String,
    pub minimum: u32,
    pub expire: u32,
    pub retry: u32,
    pub refresh: u32,
    pub serial: u32,
    pub rname: String,
    pub mname: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Ns {
    pub name: String,
    pub host: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct A {
    pub name: String,
    pub ip: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Aaaa {
    pub name: String,
    pub ip: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Cname {
    pub name: String,
    pub alias: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Mx {
    pub name: String,
    pub preference: u16,
    pub host: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Txt {
    pub name: String,
    pub txt: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Ptr {
    pub name: String,
    pub fullname: String,
    pub host: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Srv {
    pub name: String,
    pub target: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Spf {
    pub name: String,
    pub data: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Caa {
    pub name: String,
    pub flags: u8,
    pub tag: String,
    pub value: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
pub struct Ds {
    pub name: String,
    pub key_tag: String,
    pub algorithm: String,
    pub digest_type: String,
    pub digest: String,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature="paperclip", derive(Apiv2Schema))]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature="serde", serde(rename_all = "camelCase"))]
pub struct DnsZone {
    #[cfg_attr(feature="serde", serde(rename = "$origin",skip_serializing_if = "Option::is_none"))]
    pub origin: Option<String>,
    #[cfg_attr(feature="serde", serde(rename = "$ttl", skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u32>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub soa: Option<Soa>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ns: Option<Vec<Ns>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub a: Option<Vec<A>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub aaaa: Option<Vec<Aaaa>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub cname: Option<Vec<Cname>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mx: Option<Vec<Mx>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub txt: Option<Vec<Txt>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ptr: Option<Vec<Ptr>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub srv: Option<Vec<Srv>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub spf: Option<Vec<Spf>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub caa: Option<Vec<Caa>>,
    #[cfg_attr(feature="serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ds: Option<Vec<Ds>>,
}

impl DnsZone {
    pub fn is_empty(&self) -> bool {
        self.origin.is_none()
            && self.ttl.is_none()
            && self.soa.is_none()
            && self.ns.is_none()
            && self.a.is_none()
            && self.aaaa.is_none()
            && self.cname.is_none()
            && self.mx.is_none()
            && self.txt.is_none()
            && self.ptr.is_none()
            && self.srv.is_none()
            && self.spf.is_none()
            && self.caa.is_none()
            && self.ds.is_none()
    }
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
