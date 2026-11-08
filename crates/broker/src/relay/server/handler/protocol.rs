//! The SSH protocol events of a connection: login, channel opens and
//! session requests.

use russh::server::{self, Auth, Session};
use russh::{Channel, ChannelId, Disconnect, Pty, Sig};
use ssh_key::Algorithm;
use warden_broker_proto::TargetName;

use crate::relay::session::{MAX_ENV_VARS, Program, PtyRequest, env_allowed};

use super::super::conn::ours;
use super::super::{
    GRANT_QUERY_TIMEOUT, INVALID_USER, MAX_TERM_LEN, NO_AGENT, NO_FORWARDING, NO_LONGER_VALID,
    NO_SUBSYSTEMS, NO_X11, ONE_SESSION,
};
use super::{Login, RelayHandler};

impl server::Handler for RelayHandler {
    type Error = russh::Error;

    fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        // Approved keys are Ed25519; anything else is not worth a signature.
        std::future::ready(Ok(
            if offer.public_key.algorithm() == russh::keys::Algorithm::Ed25519 {
                Auth::Accept
            } else {
                Auth::reject()
            },
        ))
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        verified: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let Ok(target) = TargetName::try_from(user.to_owned()) else {
            self.conn.refused(INVALID_USER);
            return Ok(Auth::reject());
        };
        let key = ours(verified.public_key).filter(|key| key.algorithm() == Algorithm::Ed25519);
        // Bounded like every grant query, not only by the login timeout: a
        // lookup that does not answer in time refuses the attempt.
        let grant = match &key {
            Some(key) => {
                let lookup = self.shared.requests.active_relay_grant(&target, key);
                match tokio::time::timeout(GRANT_QUERY_TIMEOUT, lookup).await {
                    Ok(Ok(grant)) => grant,
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "relay: login check failed");
                        None
                    }
                    Err(_) => {
                        tracing::error!(timeout = ?GRANT_QUERY_TIMEOUT, "relay: login check timed out");
                        None
                    }
                }
            }
            None => None,
        };
        if let (Some(grant), Some(key)) = (grant, key) {
            self.login = Some(Login { grant, key });
            return Ok(Auth::Accept);
        }
        self.conn.refused(target.as_str());
        Ok(Auth::reject())
    }

    fn auth_succeeded(
        &mut self,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.preauth = None;
        let _ = self.conn.logged_in.send(true);
        let Some(login) = &self.login else {
            return std::future::ready(session.disconnect(
                Disconnect::ByApplication,
                NO_LONGER_VALID,
                "en",
            ));
        };
        self.logged_in.raise();
        let grant = &login.grant;
        std::future::ready(match self.shared.slots.try_acquire(&grant.grant_id) {
            Ok(slot) => {
                tracing::info!(grant = %grant.grant_id, agent = %grant.agent, target = %grant.target, "relay: agent logged in");
                self.slot = Some(slot);
                Ok(())
            }
            Err(refusal) => {
                tracing::warn!(grant = %grant.grant_id, agent = %grant.agent, limit = refusal.message(), "relay: session limit reached");
                session.disconnect(Disconnect::TooManyConnections, refusal.message(), "en")
            }
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.slot.is_none() || self.session_id.is_some() {
            self.refuse_open(reply, ONE_SESSION).await;
        } else {
            self.session_id = Some(channel.id());
            self.channel = Some(channel);
            reply.accept().await;
        }
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<server::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_open(reply, NO_X11).await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_open(reply, NO_FORWARDING).await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_open(reply, NO_FORWARDING).await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<server::Msg>,
        _socket_path: &str,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_open(reply, NO_FORWARDING).await;
        Ok(())
    }

    fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        self.notice(NO_FORWARDING);
        std::future::ready(Ok(false))
    }

    fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        self.notice(NO_FORWARDING);
        std::future::ready(Ok(false))
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        self.flush_notices(channel, session);
        if !self.is_session(channel)
            || self.started
            || self.pty.is_some()
            || term.len() > MAX_TERM_LEN
        {
            return session.channel_failure(channel);
        }
        self.pty = Some(PtyRequest {
            term: term.to_owned(),
            cols: col_width,
            rows: row_height,
            pix_width,
            pix_height,
            modes: modes.to_vec(),
        });
        session.channel_success(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        self.flush_notices(channel, session);
        if !self.is_session(channel)
            || self.started
            || self.env.len() >= MAX_ENV_VARS
            || !env_allowed(variable_name, variable_value)
        {
            return session.channel_failure(channel);
        }
        self.env
            .push((variable_name.to_owned(), variable_value.to_owned()));
        session.channel_success(channel)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        self.refuse_request(channel, NO_X11, session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        self.refuse_request(channel, NO_SUBSYSTEMS, session)
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(false);
        }
        // The library sends the failure reply for `false`.
        self.notice(NO_AGENT);
        self.flush_notices(channel, session);
        Ok(false)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Carried by the session task once started; counted until then.
        self.admit_before_start(data.len(), session).await?;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        _channel: ChannelId,
        _code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.admit_before_start(data.len(), session).await?;
        Ok(())
    }

    async fn signal(
        &mut self,
        _channel: ChannelId,
        _signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Forwarded by the session task once started.
        self.admit_before_start(0, session).await?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, Program::Shell, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, Program::Exec(data.to_vec()), session)
            .await
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        // A running session gets the change from the relay loop; before the
        // start, the pty to be requested takes the new size.
        if let Some(pty) = &mut self.pty
            && !self.started
        {
            pty.cols = col_width;
            pty.rows = row_height;
            pty.pix_width = pix_width;
            pty.pix_height = pix_height;
        }
        if self.is_session(channel) {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }
}
