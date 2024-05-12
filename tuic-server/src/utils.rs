use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::Item;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    fs::{File},
    io::{BufReader},
    path::PathBuf,
    str::FromStr,
};



pub fn load_certs(filename: PathBuf) -> Vec<CertificateDer<'static>> {
    let file = File::open(filename).expect("Failed to open file");
    let mut reader = BufReader::new(file);
    let mut certs = Vec::new();

    while let Ok(Some(item)) =  rustls_pemfile::read_one(&mut reader) {
        match item {
            Item::X509Certificate(cert) => {
                certs.push(cert);
            }
            _ => continue, // Skip other items
        }
    }

    if certs.is_empty() {
        // If no X.509 certificates were found, fall back to rustls_pemfile::certs
        certs = rustls_pemfile::certs(&mut reader)
            .map(|result| result.unwrap())
            .collect();
    }

    certs
}


pub fn load_priv_key(filename: PathBuf) -> PrivateKeyDer<'static> {
    let keyfile = File::open(&filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(Item::Pkcs1Key(key)) => return key.into(),
            Some(Item::Pkcs8Key(key)) => return key.into(),
            Some(Item::Sec1Key(key)) => return key.into(),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}



#[derive(Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

impl Display for UdpRelayMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Native => write!(f, "native"),
            Self::Quic => write!(f, "quic"),
        }
    }
}

pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

impl FromStr for CongestionControl {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("cubic") {
            Ok(Self::Cubic)
        } else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
            Ok(Self::NewReno)
        } else if s.eq_ignore_ascii_case("bbr") {
            Ok(Self::Bbr)
        } else {
            Err("invalid congestion control")
        }
    }
}
