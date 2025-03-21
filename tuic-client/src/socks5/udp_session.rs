use crate::error::Error;
use bytes::Bytes;
use once_cell::sync::OnceCell;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_proto::{Address, UdpHeader};
use socks5_server::AssociatedUdpSocket;
use std::{
    collections::HashMap,
    io::{Error as IoError, ErrorKind},
    net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
};

use tokio::net::UdpSocket;
use tokio::sync::RwLock as AsyncRwLock;
pub static UDP_SESSIONS: OnceCell<AsyncRwLock<HashMap<u16, UdpSession>>> = OnceCell::new();

#[derive(Clone)]
pub struct UdpSession {
    socket: Arc<AssociatedUdpSocket>,
    assoc_id: u16,
    ctrl_addr: SocketAddr,
}

impl UdpSession {
    pub fn new(
        assoc_id: u16,
        ctrl_addr: SocketAddr,
        local_ip: IpAddr,
        dual_stack: Option<bool>,
        max_pkt_size: usize,
    ) -> Result<Self, Error> {
        let domain = match local_ip {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
            Error::Socket("failed to create socks5 server UDP associate socket", err)
        })?;

        if let Some(dual_stack) = dual_stack {
            socket.set_only_v6(!dual_stack).map_err(|err| {
                Error::Socket(
                    "socks5 server UDP associate dual-stack socket setting error",
                    err,
                )
            })?;
        }

        socket.set_nonblocking(true).map_err(|err| {
            Error::Socket(
                "failed setting socks5 server UDP associate socket as non-blocking",
                err,
            )
        })?;

        socket
            .bind(&SockAddr::from(SocketAddr::from((local_ip, 0))))
            .map_err(|err| {
                Error::Socket("failed to bind socks5 server UDP associate socket", err)
            })?;

        let socket = UdpSocket::from_std(StdUdpSocket::from(socket)).map_err(|err| {
            Error::Socket("failed to create socks5 server UDP associate socket", err)
        })?;
        let associated_udp_socket = AssociatedUdpSocket::new(socket, max_pkt_size);
        Ok(Self {
            socket: Arc::new(associated_udp_socket),
            assoc_id,
            ctrl_addr,
        })
    }

    pub async fn send(&self, pkt: Bytes, src_addr: Address) -> Result<(), Error> {
        let src_addr_display = src_addr.to_string();
        log::debug!(
            "[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] send packet from {src_addr_display} to {dst_addr}",
            ctrl_addr = self.ctrl_addr,
            assoc_id = self.assoc_id,
            dst_addr = self.socket.get_ref().peer_addr().unwrap(),
        );

        let header = UdpHeader::new(0, src_addr);
        if let Err(err) = self.socket.send(pkt, &header).await {
            log::warn!(
                "[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] send packet from {src_addr_display} error: {err}",
                ctrl_addr = self.ctrl_addr,
                assoc_id = self.assoc_id,
            );

            return Err(Error::Io(err));
        }

        Ok(())
    }

    pub async fn recv(&self) -> Result<(Bytes, Address), Error> {
        let (pkt, udp_header, src_addr) = match self.socket.recv_from().await {
            Ok((pkt, udp_header, src_addr)) => (pkt, udp_header, src_addr),
            Err((err, _)) => {
                let msg = format!("recv from error: {err}");
                return Err(IoError::new(ErrorKind::Other, msg))?;
            }
        };
        let dst_addr = udp_header.address;
        let frag = udp_header.frag;

        if let Ok(connected_addr) = self.socket.get_ref().peer_addr() {
            let connected_addr = match connected_addr {
                SocketAddr::V4(addr) => {
                    if let SocketAddr::V6(_) = src_addr {
                        SocketAddr::new(addr.ip().to_ipv6_mapped().into(), addr.port())
                    } else {
                        connected_addr
                    }
                }
                SocketAddr::V6(addr) => {
                    if let SocketAddr::V4(_) = src_addr {
                        if let Some(ip) = addr.ip().to_ipv4_mapped() {
                            SocketAddr::new(IpAddr::V4(ip), addr.port())
                        } else {
                            connected_addr
                        }
                    } else {
                        connected_addr
                    }
                }
            };
            if src_addr != connected_addr {
                Err(IoError::new(
                    ErrorKind::Other,
                    format!("invalid source address: {src_addr}"),
                ))?;
            }
        } else {
            self.socket.get_ref().connect(src_addr).await?;
        }

        if frag != 0 {
            Err(IoError::new(
                ErrorKind::Other,
                "fragmented packet is not supported",
            ))?;
        }

        log::debug!(
            "[socks5] [{ctrl_addr}] [associate] [{assoc_id:#06x}] receive packet from {src_addr} to {dst_addr}",
            ctrl_addr = self.ctrl_addr,
            assoc_id = self.assoc_id
        );

        Ok((pkt, dst_addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, IoError> {
        self.socket.get_ref().local_addr()
    }
}
