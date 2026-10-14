//! Isolated-kernel fixture: apply a real authorized commit, then drop its reply.
//! No injection switch is added to the installed netd executable.
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{bail, Result};
    use candy_netd::v2::{InfrastructureJournal, InfrastructureService};
    use candy_netd::{
        bind_private_socket, peer_credentials, LinuxNetworkBackend, SystemTunFactory,
    };
    use candy_netd_client::v2::{recv_request_until, send_response_until};
    use candy_netd_proto::v2::{Body, Operation, Response};
    use clap::Parser;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        protocol_v2: bool,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        allowed_uid: u32,
        #[arg(long)]
        allowed_gid: u32,
        #[arg(long)]
        infrastructure_journal: PathBuf,
        #[arg(long)]
        fault_evidence: PathBuf,
    }

    pub fn run() -> Result<()> {
        let args = Args::parse();
        if std::env::var("CANDY_NETD_ISOLATED_KERNEL_TEST").as_deref() != Ok("1")
            || !args.protocol_v2
            || args.allowed_uid != 0
            || args.allowed_gid != 0
            || nix::unistd::geteuid().as_raw() != 0
        {
            bail!("isolated privileged kernel fixture gate is required");
        }
        let listener = bind_private_socket(&args.socket)?;
        listener.set_nonblocking(true)?;
        let mut service = InfrastructureService::new(
            0,
            0,
            SystemTunFactory,
            LinuxNetworkBackend::new()?,
            InfrastructureJournal::new(&args.infrastructure_journal)?,
        )?;
        let mut dropped = false;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let peer = peer_credentials(&stream)?;
                    let request = recv_request_until(&stream, deadline)?;
                    let lost_receipt = match &request.operation {
                        Operation::ForwardCommitAuthorized { receipt, .. } if !dropped => {
                            Some(receipt.clone())
                        }
                        _ => None,
                    };
                    let request_id = request.request_id;
                    let processed =
                        service.process(request, peer, candy_netd::v2::clock::now_ms()?);
                    let (body, fd) = match processed {
                        Ok(result) => result,
                        Err(error) => (
                            Body::Error {
                                code: "fixture_request_failed".into(),
                                module: "netd_reply_loss_fixture".into(),
                                reason: error.to_string(),
                            },
                            None,
                        ),
                    };
                    if let Some(receipt) = lost_receipt.filter(|_| matches!(body, Body::Ack)) {
                        let journal = args
                            .socket
                            .parent()
                            .unwrap()
                            .join("worker-process.renewal.json");
                        let phase =
                            serde_json::from_slice::<serde_json::Value>(&fs::read(journal)?)?
                                ["phase"]
                                .clone();
                        let evidence = serde_json::json!({
                            "request_id":request_id,
                            "committed_success_before_drop":true,
                            "reply_drops":1,
                            "journal_phase_before_reply_drop":phase,
                            "candidate_pid":receipt.authority.candidate_pid,
                            "candidate_start_ticks":receipt.authority.candidate_start_ticks,
                            "transaction_id":receipt.authority.transaction_id,
                        });
                        let mut output = OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .mode(0o600)
                            .open(&args.fault_evidence)?;
                        output.write_all(&serde_json::to_vec(&evidence)?)?;
                        output.sync_all()?;
                        dropped = true;
                        eprintln!("signed_commit_reply_loss_injected actual_commit=true actual_peer_credentials=true candidate_pid={} journal_phase={} reply_drops=1",receipt.authority.candidate_pid,phase);
                        // Dropping this authenticated stream loses only the reply after durable commit.
                        continue;
                    }
                    if let Err(error) = send_response_until(
                        &stream,
                        &Response { request_id, body },
                        fd.as_ref(),
                        deadline,
                    ) {
                        eprintln!("signed_commit_reply_loss_fixture_response_failed error={error}");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            service.recover_expired(candy_netd::v2::clock::now_ms()?)?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("signed commit reply loss fixture requires Linux");
}
