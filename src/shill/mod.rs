//! Experimental, Shill-inspired capability executor. Not the Harvard Shill runtime.
//!
//! All effects require a fresh authenticated transport record, native CBCL admission,
//! an exact local resource/program binding and a durable single-use thread claim.
//! The parent process remains trusted; only fixed child programs enter an OS sandbox.

mod journal;
mod kernel;
mod policy;
mod process;
#[cfg(test)]
mod tests;

use crate::{
    daemon::AgentHandle,
    local_api::{
        LocalApiClient, ObjectActRequest, ObjectOpenRequest, SendMessageKind, SendRequest,
    },
    object_transport::AttestedBy,
};
use clap::{Args, Subcommand};
use journal::Journal;
use kernel::{Authority, Authorized, Decision, Effect};
use policy::Policy;
use serde_json::json;
use std::{path::PathBuf, time::Instant};

type Result<T> = anyhow::Result<T>;
fn fail<T>(message: &str) -> Result<T> {
    Err(anyhow::anyhow!("{message}"))
}

#[derive(Debug, Subcommand)]
pub enum ShillCommand {
    /// Print the version-3 object definition (local; no daemon or effects).
    Definition,
    /// Validate local bindings and print the compiled dialect; invokes no programs.
    Check {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Consume a dedicated agent's object queue and execute admitted capabilities.
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[arg(long)]
    manifest: PathBuf,
    /// Private durable directory. Existing claims are never automatically discarded.
    #[arg(long)]
    journal: PathBuf,
    /// Permit hub-attested public-room requests/output; default requires MLS.
    #[arg(long)]
    allow_public: bool,
}

impl ShillCommand {
    pub(crate) fn needs_agent(&self) -> bool {
        matches!(self, Self::Serve(_))
    }
}

pub(crate) async fn command(
    command: ShillCommand,
    connection: Option<(LocalApiClient, AgentHandle)>,
) -> Result<()> {
    match command {
        ShillCommand::Definition => {
            println!("{}", serde_json::to_string_pretty(&kernel::definition())?)
        }
        ShillCommand::Check { manifest } => {
            let policy = Policy::load(&manifest)?;
            let dialect = kernel::Dialect::new()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "experimental":true,"dialect":dialect.name,"cbcl":dialect.cbcl,
                    "resources":policy.snapshots.keys().collect::<Vec<_>>(),
                    "programs":policy.manifest.programs.keys().collect::<Vec<_>>(),
                    "directories":policy.directories.keys().collect::<Vec<_>>(),
                    "provenance":policy.manifest.provenance
                }))?
            );
        }
        ShillCommand::Serve(args) => {
            let (client, handle) =
                connection.ok_or_else(|| anyhow::anyhow!("daemon connection required"))?;
            let policy = Policy::load(&args.manifest)?;
            if policy.manifest.provenance == AttestedBy::Hub && !args.allow_public {
                return fail(
                    "public-room execution requires --allow-public; output will be public",
                );
            }
            let authority = Authority::new(policy)?;
            let journal = Journal::open(&args.journal, authority.policy.manifest.max_commands)?;
            validate_connection(&client, &handle, &authority).await?;
            // Object open declares the dialect using Hark's CONTROL path. Generic
            // send would MLS-seal an adddialect frame, hiding it from the hub.
            let offer_thread = format!("shill-offer-{}", &authority.session[..16]);
            let offer = client
                .object_open(
                    &handle,
                    &ObjectOpenRequest {
                        definition: kernel::definition(),
                        thread: offer_thread.clone(),
                        fields: json!({"session":authority.session}),
                    },
                )
                .await
                .map_err(|error| {
                    anyhow::anyhow!("declare worker offer (join with --objects): {error:?}")
                })?;
            if !offer.ok || offer.dialect != authority.dialect.name {
                return fail("daemon refused or compiled a different worker dialect");
            }
            println!(
                "{}",
                json!({"ready":true,"experimental":true,"session":authority.session,
                "dialect":authority.dialect.name,"controller":authority.policy.manifest.controller,
                "room":authority.policy.manifest.room,"lifetime_seconds":authority.policy.manifest.lifetime_seconds,
                "offer_thread":offer_thread,"definition":kernel::definition()})
            );
            // A cancelled serve future drops the child process-group guard before returning.
            tokio::select! {
                result = serve(authority, journal, client, handle) => result?,
                result = shutdown() => { result?; }
            }
        }
    }
    Ok(())
}

async fn shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(())
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

async fn validate_connection(
    client: &LocalApiClient,
    handle: &AgentHandle,
    authority: &Authority,
) -> Result<()> {
    let agents = client
        .agents()
        .await
        .map_err(|error| anyhow::anyhow!("daemon agents: {error:?}"))?;
    let agent = agents
        .agents
        .iter()
        .find(|agent| agent.agent_handle == handle.as_str())
        .ok_or_else(|| anyhow::anyhow!("selected worker is not registered"))?;
    let manifest = &authority.policy.manifest;
    let expected = if authority.provenance() == AttestedBy::Mls {
        "mls"
    } else {
        "none"
    };
    if agent.router_agent_id != manifest.worker
        || agent.channel.as_deref() != Some(&manifest.room)
        || !agent.connection.as_ref().is_some_and(|c| {
            c.ready && c.hub.as_deref() == Some(&manifest.hub) && c.encryption == expected
        })
    {
        return fail(
            "selected worker identity, room, hub, readiness or encryption differs from manifest",
        );
    }
    Ok(())
}

async fn serve(
    mut authority: Authority,
    mut journal: Journal,
    client: LocalApiClient,
    handle: AgentHandle,
) -> Result<()> {
    let expiry = tokio::time::Instant::now() + authority.remaining();
    loop {
        let envelope = tokio::select! {
            result = client.recv(&handle, None) => result.map_err(|error| anyhow::anyhow!("daemon receive: {error:?}"))?,
            _ = tokio::time::sleep_until(expiry) => return Ok(())
        };
        let mut queue = std::collections::VecDeque::from([envelope]);
        while let Some(envelope) = queue.pop_front() {
            if authority.expired() {
                return Ok(());
            }
            let decision = match authority.receive(envelope) {
                Ok(decision) => decision,
                Err(error) => {
                    tracing::warn!(%error, "shill refused request");
                    continue;
                }
            };
            match decision {
                Decision::Ignored | Decision::Unknown => {}
                Decision::Opened => {
                    queue.extend(std::mem::take(&mut authority.pending).into_values())
                }
                Decision::Valid(capability) => {
                    // Fail closed if the daemon's current connection changed since startup.
                    validate_connection(&client, &handle, &authority).await?;
                    if let Err(error) =
                        perform(&authority, &mut journal, &client, &handle, capability).await
                    {
                        tracing::warn!(%error, uptime_ms=authority.uptime_ms(), "shill effect refused or delivery uncertain");
                    }
                }
            }
        }
    }
}

async fn send(client: &LocalApiClient, handle: &AgentHandle, message: String) -> Result<()> {
    client
        .send(
            handle,
            &SendRequest {
                kind: SendMessageKind::Send,
                message,
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("daemon send: {error:?}"))?;
    Ok(())
}

async fn perform(
    authority: &Authority,
    journal: &mut Journal,
    client: &LocalApiClient,
    handle: &AgentHandle,
    capability: Authorized,
) -> Result<()> {
    if authority.expired() {
        return fail("worker session expired before execution");
    }
    let manifest = &authority.policy.manifest;
    let claim = journal.claim(
        &manifest.room,
        &manifest.controller,
        &capability.thread,
        &capability.cid,
    )?;
    let started = Instant::now();
    let (output, code) = match capability.effect {
        Effect::Read(snapshot) => (snapshot.to_string(), 0),
        Effect::Run(program) => match process::run(&program).await {
            Ok(result) => (format!("{}{}", result.stdout, result.stderr), result.code),
            Err(error) => (format!("Bounded program failed: {error}"), 1),
        },
        Effect::Invoke(program, arguments) => match process::invoke(&program, &arguments).await {
            Ok(result) => (format!("{}{}", result.stdout, result.stderr), result.code),
            Err(error) => (format!("Bounded program failed: {error}"), 1),
        },
    };
    // Persist the known execution result before attempting network delivery. A lost
    // response never justifies repeating an already exercised capability.
    claim.complete(code)?;
    let elapsed = started.elapsed().as_micros().min(1_000_000_000) as u64;
    let chunks = chunks(&output);
    for (index, data) in chunks.iter().enumerate() {
        reply(
            authority,
            client,
            handle,
            &capability.thread,
            &capability.records,
            ObjectActRequest {
                verb: "output".into(),
                fields: json!({"seq":index+1,"data":data}),
            },
        )
        .await?;
    }
    reply(
        authority,
        client,
        handle,
        &capability.thread,
        &capability.records,
        ObjectActRequest {
            verb: "done".into(),
            fields: json!({"number":chunks.len(),"exit-code":code,"elapsed-micros":elapsed}),
        },
    )
    .await
}

async fn reply(
    authority: &Authority,
    client: &LocalApiClient,
    handle: &AgentHandle,
    thread: &str,
    records: &[String],
    request: ObjectActRequest,
) -> Result<()> {
    // Bind against precisely this admitted command, avoiding async object discovery
    // and unrelated concurrent branches in the daemon's general object broker.
    let message = authority.dialect.intend(
        thread,
        records,
        &authority.policy.manifest.worker,
        &request.verb,
        &request.fields,
    )?;
    send(client, handle, message).await
}

fn chunks(text: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for character in text.chars() {
        if current.len() + character.len_utf8() > 1800 {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(character);
    }
    chunks.push(current);
    chunks
}
