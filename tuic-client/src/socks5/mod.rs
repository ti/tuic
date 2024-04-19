use crate::{config::Local, error::Error};
use once_cell::sync::OnceCell;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use socks5_server::{auth::Password, Auth, Command, Server as Socks5Server};

use socks5_proto::handshake::password::Error as AuthError;

use async_trait::async_trait;
use socks5_proto::handshake::Method;
use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener as StdTcpListener},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock as AsyncRwLock;

use tokio::io::AsyncWriteExt;

mod handle_task;
mod udp_session;

pub use self::udp_session::UDP_SESSIONS;

static SERVER: OnceCell<Server> = OnceCell::new();

pub struct Server {
    inner: Socks5Server<Result<bool, AuthError>>,
    dual_stack: Option<bool>,
    max_pkt_size: usize,
    next_assoc_id: AtomicU16,
}

impl Server {
    pub fn set_config(cfg: Local) -> Result<(), Error> {
        SERVER
            .set(Self::new(
                cfg.server,
                cfg.dual_stack,
                cfg.max_packet_size,
                cfg.username,
                cfg.password,
            )?)
            .map_err(|_| "failed initializing socks5 server")
            .unwrap();

        UDP_SESSIONS
            .set(AsyncRwLock::new(HashMap::new()))
            .map_err(|_| "failed initializing socks5 UDP session pool")
            .unwrap();

        Ok(())
    }

    fn new(
        addr: SocketAddr,
        dual_stack: Option<bool>,
        max_pkt_size: usize,
        username: Option<Vec<u8>>,
        password: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let socket = {
            let domain = match addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .map_err(|err| Error::Socket("failed to create socks5 server socket", err))?;

            if let Some(dual_stack) = dual_stack {
                socket.set_only_v6(!dual_stack).map_err(|err| {
                    Error::Socket("socks5 server dual-stack socket setting error", err)
                })?;
            }

            socket.set_reuse_address(true).map_err(|err| {
                Error::Socket("failed to set socks5 server socket to reuse_address", err)
            })?;

            socket.set_nonblocking(true).map_err(|err| {
                Error::Socket("failed setting socks5 server socket as non-blocking", err)
            })?;

            socket
                .bind(&SockAddr::from(addr))
                .map_err(|err| Error::Socket("failed to bind socks5 server socket", err))?;

            socket
                .listen(i32::MAX)
                .map_err(|err| Error::Socket("failed to listen on socks5 server socket", err))?;

            TcpListener::from_std(StdTcpListener::from(socket))
                .map_err(|err| Error::Socket("failed to create socks5 server socket", err))?
        };
        // let auth = Arc::new(NoAuth) as Arc<_>;

        let auth: Arc<dyn Auth<Output = Result<bool, AuthError>> + Send + Sync> =
            match (username, password) {
                (Some(username), Some(password)) => Arc::new(Password::new(username, password)),
                (None, None) => Arc::new(NoPassword {}),
                _ => return Err(Error::InvalidSocks5Auth),
            };

        Ok(Self {
            inner: Socks5Server::new(socket, auth),
            dual_stack,
            max_pkt_size,
            next_assoc_id: AtomicU16::new(0),
        })
    }

    pub async fn start() {
        let server = SERVER.get().unwrap();
        log::warn!(
            "[socks5] server started, listening on {}",
            server.inner.local_addr().unwrap()
        );

        loop {
            match server.inner.accept().await {
                Ok((conn, addr)) => {
                    log::debug!("[socks5] [{addr}] connection established");
                    tokio::spawn(async move {
                        match conn.authenticate().await {
                            Ok((conn, result)) => {
                                if let Ok(false) = result {
                                    if let Err(ref err) = result {
                                        log::warn!("[socks5] authentication failed: {}", err);
                                    } else {
                                        log::warn!("[socks5] authentication failed.");
                                    }
                                    return;
                                }
                                match conn.wait().await {
                                    Ok(Command::Associate(associate, _)) => {
                                        let assoc_id =
                                            server.next_assoc_id.fetch_add(1, Ordering::Relaxed);
                                        log::info!(
                                            "[socks5] [{addr}] [associate] [{assoc_id:#06x}]"
                                        );
                                        Self::handle_associate(
                                            associate,
                                            assoc_id,
                                            server.dual_stack,
                                            server.max_pkt_size,
                                        )
                                        .await;
                                    }
                                    Ok(Command::Bind(bind, _)) => {
                                        log::info!("[socks5] [{addr}] [bind]");
                                        Self::handle_bind(bind).await;
                                    }
                                    Ok(Command::Connect(connect, target_addr)) => {
                                        log::info!("[socks5] [{addr}] [connect] {target_addr}");
                                        Self::handle_connect(connect, target_addr).await;
                                    }
                                    Err((err, mut conn)) => {
                                        let _ = conn.shutdown().await;
                                        log::warn!("[socks5] wait error {err}")
                                    }
                                };
                            }
                            Err((err, mut conn)) => {
                                let _ = conn.shutdown().await;
                                log::warn!("[socks5] auth error {err}")
                            }
                        };
                        log::debug!("[socks5] [{addr}] connection closed");
                    });
                }
                Err(err) => log::warn!("[socks5] failed to establish connection: {err}"),
            }
        }
    }
}

// Not authenticate at all, but return success
#[derive(Clone, Debug)]
struct NoPassword {}

#[async_trait]
impl Auth for NoPassword {
    type Output = Result<bool, AuthError>;
    fn as_handshake_method(&self) -> Method {
        Method::NONE
    }
    async fn execute(&self, _: &mut TcpStream) -> Self::Output {
        Ok(true)
    }
}
