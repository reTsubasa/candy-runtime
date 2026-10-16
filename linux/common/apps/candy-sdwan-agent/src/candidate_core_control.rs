//! Authenticated management adapter for immutable cross-process handoffs.
use anyhow::{ensure, Context, Result};
use candy_process_control::{
    exchange, exchange_document, process_identity, ControlOperation, ControlRequest,
    ProcessIdentity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_CANDIDATE_CONTROL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct Request<'a> {
    schema_version: u8,
    operation: &'a str,
    token_sha256: &'a str,
    nonce: String,
    payload: &'a Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u8,
    process: ProcessIdentity,
    controller: ProcessIdentity,
    controller_epoch: u64,
    nonce: String,
    accepted: bool,
    code: String,
    #[serde(default)]
    payload: Option<Value>,
    #[serde(default)]
    detail: Option<String>,
}

pub(super) fn exchange_candidate(
    path: &Path,
    process: ProcessIdentity,
    token_sha256: &str,
    operation: &str,
    candidate: &Value,
) -> Result<Value> {
    ensure!(
        matches!(
            operation,
            "candidate_reserve"
                | "candidate_prepare"
                | "candidate_install"
                | "candidate_activate"
                | "candidate_drain"
                | "candidate_status"
                | "candidate_retire_old"
                | "candidate_retire_after_failure"
        ),
        "code=candidate_control_operation_invalid module=sdwan_handoff"
    );
    let controller = process_identity(std::process::id())?;
    let takeover = exchange(
        path,
        process,
        &ControlRequest {
            schema_version: 1,
            operation: ControlOperation::Takeover,
            token_sha256: token_sha256.to_owned(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
        },
    )?;
    ensure!(
        takeover.controller == controller && takeover.controller_epoch != 0,
        "code=candidate_control_controller_mismatch module=sdwan_handoff"
    );
    let request = Request {
        schema_version: 1,
        operation,
        token_sha256,
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        payload: candidate,
    };
    let response: Response = exchange_document(
        path,
        process,
        &request,
        MAX_CANDIDATE_CONTROL_BYTES,
        Instant::now() + Duration::from_secs(2),
    )?;
    validate_response(
        &response,
        process,
        controller,
        takeover.controller_epoch,
        &request.nonce,
    )?;
    response.payload.context("code=candidate_control_receipt_missing module=sdwan_handoff action=reconcile_original_transaction")
}

fn validate_response(
    response: &Response,
    process: ProcessIdentity,
    controller: ProcessIdentity,
    controller_epoch: u64,
    nonce: &str,
) -> Result<()> {
    ensure!(response.schema_version == 1 && response.process == process
        && response.controller == controller && response.controller_epoch == controller_epoch
        && response.nonce == nonce,
        "code=candidate_control_receipt_mismatch module=sdwan_handoff action=reconcile_original_transaction");
    ensure!(
        response.accepted,
        "code={} module=sdwan_handoff detail={} action=reconcile_original_transaction",
        response.code,
        response.detail.as_deref().unwrap_or("no_detail")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_reply_requires_exact_process_controller_epoch_and_challenge() {
        let process = ProcessIdentity {
            pid: 10,
            start_ticks: 20,
        };
        let controller = ProcessIdentity {
            pid: 30,
            start_ticks: 40,
        };
        let mut reply = Response {
            schema_version: 1,
            process,
            controller,
            controller_epoch: 2,
            nonce: "aa".repeat(16),
            accepted: true,
            code: "ok".into(),
            payload: Some(serde_json::json!({"phase":"installed"})),
            detail: None,
        };
        assert!(validate_response(&reply, process, controller, 2, &reply.nonce).is_ok());
        for field in ["process", "controller", "epoch", "nonce", "rejected"] {
            reply.process = process;
            reply.controller = controller;
            reply.controller_epoch = 2;
            reply.nonce = "aa".repeat(16);
            reply.accepted = true;
            match field {
                "process" => reply.process.start_ticks += 1,
                "controller" => reply.controller.start_ticks += 1,
                "epoch" => reply.controller_epoch += 1,
                "nonce" => reply.nonce = "bb".repeat(16),
                _ => reply.accepted = false,
            }
            assert!(validate_response(&reply, process, controller, 2, &"aa".repeat(16)).is_err());
        }
    }
}
