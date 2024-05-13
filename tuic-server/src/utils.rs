use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::Item;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    fs::{File},
    io::{BufReader, Error as IoError},
    path::PathBuf,
    str::FromStr,
};
use std::io::ErrorKind;


pub fn load_certs(path: PathBuf) -> Result<Vec<CertificateDer<'static>>, IoError> {
    let file = BufReader::new(File::open(path)?);
    let mut certs = Vec::new();
    let mut reader = BufReader::new(file);

    while let Ok(Some(item)) = rustls_pemfile::read_one(&mut reader) {
        if let Item::X509Certificate(cert) = item {
            certs.push(cert);
        }
    }

    if certs.is_empty() {
        certs = rustls_pemfile::certs(&mut reader)
            .map(|result| result.unwrap())
            .collect();
    }

    Ok(certs)
}



pub fn load_priv_key(filename: PathBuf) -> Result<PrivateKeyDer<'static>, IoError> {
    let keyfile = File::open(&filename)?;
    let mut reader = BufReader::new(keyfile);

    while let Ok(Some(item)) = rustls_pemfile::read_one(&mut reader) {
        match item {
            Item::Pkcs1Key(key) => return Ok(key.into()),
            Item::Pkcs8Key(key) => return Ok(key.into()),
            Item::Sec1Key(key) => return Ok(key.into()),
            _ => {}
        }
    }

    Err(IoError::new(
        ErrorKind::InvalidData,
        format!("no keys found in {:?}", filename),
    ))
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
