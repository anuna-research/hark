//! Paths never cross this API: callers supply bytes and save verified bytes.
use super::*;
use crate::media::{self, Descriptor, MediaError};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

// Bound encrypted/plaintext buffers, inspection processes and network transfers
// across all agents. A refused operation performs no storage request.
static TRANSFERS: Semaphore = Semaphore::const_new(4);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaUploadRequest {
    pub data: String,
    pub title: String,
    #[serde(default)]
    pub caption: String,
    #[serde(default)]
    pub allow_public: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct MediaAttachment {
    pub thread: String,
    pub title: String,
    pub caption: String,
    #[serde(rename = "type")]
    pub mime: String,
    /// Plaintext byte length.
    pub size: usize,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct MediaUploadResponse {
    pub ok: bool,
    pub attachment: MediaAttachment,
    pub cid: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct MediaListResponse {
    pub attachments: Vec<MediaAttachment>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaDownloadRequest {
    pub thread: String,
}
#[derive(Serialize, Deserialize)]
pub struct MediaDownloadResponse {
    pub attachment: MediaAttachment,
    pub data: String,
}

fn failure(error: MediaError) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "media_failed",
        error.0,
        None,
    )
}
fn busy() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "media_busy",
        "four media transfers are active; retry shortly",
        None,
    )
}
fn bad(message: &str) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "malformed_media_request",
        message,
        None,
    )
}
async fn ready(
    store: &AgentStore,
    handle: &AgentHandle,
    allow_public: Option<bool>,
) -> Result<(), ApiError> {
    let status = store
        .status_snapshots()
        .await
        .into_iter()
        .find(|s| s.agent_handle == handle.as_str())
        .ok_or_else(|| agent_error_to_api(AgentError::UnknownHandle))?;
    if status.state != crate::daemon::AgentState::Connected
        || status.readiness_reason.is_some()
        || !["none", "mls"].contains(&status.encryption.as_str())
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "media_not_ready",
            "agent must have a ready room session; inspect hark whoami --json",
            None,
        ));
    }
    if allow_public == Some(false) && status.encryption != "mls" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "public_media_confirmation_required",
            "the hub and everyone in this room can read the file; use --allow-public to acknowledge this",
            None,
        ));
    }
    Ok(())
}
fn attachment(thread: String, state: &Value) -> Result<(MediaAttachment, Descriptor), ApiError> {
    let reference = state["ref"]
        .as_str()
        .ok_or_else(|| bad("file object has no attachment descriptor"))?;
    let descriptor = Descriptor::parse(reference).map_err(failure)?;
    Ok((
        MediaAttachment {
            thread,
            title: state["title"].as_str().unwrap_or_default().into(),
            caption: state["caption"].as_str().unwrap_or_default().into(),
            mime: descriptor.mime.clone(),
            size: descriptor.size - 48,
        },
        descriptor,
    ))
}
pub(super) async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Json(request): Json<MediaUploadRequest>,
) -> Result<Json<MediaUploadResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    let _permit = TRANSFERS.try_acquire().map_err(|_| busy())?;
    let handle = parse_handle(handle)?;
    let (objects, who) = state
        .agents
        .objects_for(&handle)
        .await
        .map_err(agent_error_to_api)?;
    ready(&state.agents, &handle, Some(request.allow_public)).await?;
    if request.title.trim().is_empty()
        || request.title.len() > 1024
        || request.caption.len() > 16_384
    {
        return Err(bad(
            "title must be nonempty and at most 1024 bytes; caption at most 16384 bytes",
        ));
    }
    if request.data.len() > media::MAX_PLAINTEXT_BYTES.div_ceil(3) * 4 {
        return Err(bad("media exceeds 8 MiB encrypted-file limit"));
    }
    let bytes = STANDARD
        .decode(&request.data)
        .map_err(|_| bad("data must be standard base64"))?;
    let mime = media::inspect(&bytes, None).await.map_err(failure)?;
    objects
        .check(media::file_definition())
        .await
        .map_err(objects_error_to_api)?;
    let (descriptor, stored) = media::seal(&bytes, &mime).map_err(failure)?;
    let digest = descriptor.digest().map_err(failure)?;
    ready(&state.agents, &handle, Some(request.allow_public)).await?;
    let reserved = media::control(
        &state.agents,
        &handle,
        &who.room,
        &who.me,
        "upload",
        &format!(":h \"{digest}\" :n {}", stored.len()),
    )
    .await
    .map_err(failure)?;
    media::put(
        &state.media_http,
        reserved.text("url").map_err(failure)?,
        stored,
    )
    .await
    .map_err(failure)?;
    ready(&state.agents, &handle, Some(request.allow_public)).await?;
    media::control(
        &state.agents,
        &handle,
        &who.room,
        &who.me,
        "commit",
        &format!(":upload \"{}\"", reserved.text("upload").map_err(failure)?),
    )
    .await
    .map_err(failure)?;
    let thread = format!("file-{}", media::to_hex(&rand::random::<[u8; 16]>()));
    let fields = json!({"title":request.title,"caption":request.caption,"ref":descriptor.render().map_err(failure)?});
    ready(&state.agents, &handle, Some(request.allow_public)).await?;
    let outcome = objects
        .open(who, media::file_definition(), thread.clone(), fields)
        .await
        .map_err(objects_error_to_api)?;
    if !outcome.ok {
        return Err(failure(MediaError(format!(
            "file committed but posting failed: {}",
            outcome.reason.unwrap_or_default()
        ))));
    }
    Ok(Json(MediaUploadResponse {
        ok: true,
        attachment: MediaAttachment {
            thread,
            title: request.title,
            caption: request.caption,
            mime,
            size: bytes.len(),
        },
        cid: outcome.cid.unwrap_or_default(),
    }))
}
pub(super) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<Json<MediaListResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    let handle = parse_handle(handle)?;
    let (objects, who) = state
        .agents
        .objects_for(&handle)
        .await
        .map_err(agent_error_to_api)?;
    let file = objects
        .check(media::file_definition())
        .await
        .map_err(objects_error_to_api)?
        .dialect;
    let mut attachments = Vec::new();
    for object in objects
        .list(who.clone())
        .await
        .map_err(objects_error_to_api)?
    {
        if object.dialect != file {
            continue;
        }
        if let Some(object) = objects
            .read(who.clone(), object.thread.clone())
            .await
            .map_err(objects_error_to_api)?
        {
            if let Ok((item, _)) = attachment(object.thread, &object.state) {
                attachments.push(item)
            }
        }
    }
    Ok(Json(MediaListResponse { attachments }))
}
pub(super) async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
    Json(request): Json<MediaDownloadRequest>,
) -> Result<Json<MediaDownloadResponse>, ApiError> {
    authorize(&state, &headers)?;
    reject_if_stopping(&state)?;
    let _permit = TRANSFERS.try_acquire().map_err(|_| busy())?;
    let handle = parse_handle(handle)?;
    let (objects, who) = state
        .agents
        .objects_for(&handle)
        .await
        .map_err(agent_error_to_api)?;
    ready(&state.agents, &handle, None).await?;
    let file = objects
        .check(media::file_definition())
        .await
        .map_err(objects_error_to_api)?
        .dialect;
    let object = objects
        .read(who.clone(), request.thread)
        .await
        .map_err(objects_error_to_api)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "unknown_media_thread",
                "attachment is absent from learned history; use hark media list or hark history",
                None,
            )
        })?;
    if object.dialect != file {
        return Err(bad("thread is not a file object"));
    }
    let (attachment, descriptor) = attachment(object.thread, &object.state)?;
    let reply = media::control(
        &state.agents,
        &handle,
        &who.room,
        &who.me,
        "get",
        &format!(":h \"{}\"", descriptor.digest().map_err(failure)?),
    )
    .await
    .map_err(failure)?;
    let stored = media::get(
        &state.media_http,
        reply.text("url").map_err(failure)?,
        descriptor.size,
    )
    .await
    .map_err(failure)?;
    let plaintext = descriptor.open(&stored).map_err(failure)?;
    media::inspect(&plaintext, Some(&descriptor.mime))
        .await
        .map_err(failure)?;
    ready(&state.agents, &handle, None).await?;
    Ok(Json(MediaDownloadResponse {
        attachment,
        data: STANDARD.encode(plaintext),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};

    async fn fixture() -> (
        AppState,
        AgentHandle,
        HeaderMap,
        tokio::sync::mpsc::Receiver<crate::daemon::OutboundFrame>,
    ) {
        let agents = AgentStore::new(crate::daemon::AgentStoreConfig {
            agent_id_prefix: "media-test".into(),
            max_messages_per_handle: 32,
            max_bytes_per_handle: 65536,
        });
        let handle = AgentHandle::try_from("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        agents
            .insert_connected_with_router_channels(
                handle.clone(),
                vec![],
                None,
                Some(crate::daemon::AgentSendChannel::new(tx)),
                Some("@aria".into()),
                Some("@general".into()),
            )
            .await
            .unwrap();
        agents.mark_objects(&handle, true).await.unwrap();
        agents
            .set_session_readiness(&handle, "none", None)
            .await
            .unwrap();
        agents
            .attach_objects(crate::objects::runtime::spawn(
                agents.clone(),
                tokio::runtime::Handle::current(),
                None,
            ))
            .await;
        let record = DiscoveryRecord {
            started_at: time::OffsetDateTime::now_utc(),
            pid: std::process::id(),
            addr: "127.0.0.1:12345".parse().unwrap(),
            token: "media-test-token".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            api_version: crate::constants::LOCAL_API_VERSION,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer media-test-token"),
        );
        let state = AppState {
            media_http: media::http().unwrap(),
            record: Arc::new(record),
            agents,
            config: Arc::new(AppConfig::default()),
            stop: Arc::new(StopState {
                discovery_file: None,
                stopping: AtomicBool::new(false),
                shutdown_tx: Mutex::new(None),
            }),
        };
        (state, handle, headers, rx)
    }
    fn request(allow_public: bool) -> MediaUploadRequest {
        MediaUploadRequest {
            data: STANDARD.encode(wav()),
            title: "sample.wav".into(),
            caption: "A short sound".into(),
            allow_public,
        }
    }
    fn wav() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(b"RIFF");
        b.extend(196u32.to_le_bytes());
        b.extend(b"WAVEfmt ");
        b.extend(16u32.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(8000u32.to_le_bytes());
        b.extend(16000u32.to_le_bytes());
        b.extend(2u16.to_le_bytes());
        b.extend(16u16.to_le_bytes());
        b.extend(b"data");
        b.extend(160u32.to_le_bytes());
        b.extend([0; 160]);
        b
    }
    #[tokio::test]
    async fn media_api_refuses_public_without_consent_and_unready_private_sessions() {
        let (state, handle, headers, mut rx) = fixture().await;
        let response = upload(
            State(state.clone()),
            headers.clone(),
            Path(handle.as_str().into()),
            Json(request(false)),
        )
        .await
        .unwrap_err();
        assert_eq!(response.code, "public_media_confirmation_required");
        assert!(rx.try_recv().is_err());
        state
            .agents
            .set_session_readiness(&handle, "mls", Some("awaiting MLS Welcome".into()))
            .await
            .unwrap();
        let response = upload(
            State(state.clone()),
            headers.clone(),
            Path(handle.as_str().into()),
            Json(request(false)),
        )
        .await
        .unwrap_err();
        assert_eq!(response.code, "media_not_ready");
        assert!(rx.try_recv().is_err());
        let response = list(
            State(state.clone()),
            HeaderMap::new(),
            Path(handle.as_str().into()),
        )
        .await
        .unwrap_err();
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        state.agents.close(&handle).await.unwrap();
    }
    #[tokio::test]
    async fn media_api_upload_list_download_with_real_https_storage() {
        let (mut state, handle, _headers, mut rx) = fixture().await;
        let mut storage = tokio::process::Command::new("node")
            .arg("tests/vectors/media/storage.mjs")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(storage.stdout.take().unwrap()).lines();
        let port = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let base = format!("https://127.0.0.1:{port}");
        state.media_http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .add_root_certificate(
                reqwest::Certificate::from_pem(include_bytes!(
                    "../../tests/vectors/media/root-cert.pem"
                ))
                .unwrap(),
            )
            .build()
            .unwrap();
        let store = state.agents.clone();
        let agent = handle.clone();
        let url = base.clone();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let log = sent.clone();
        let relay = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let text = frame.message.clone();
                let control = frame.control;
                log.lock().unwrap().push((text.clone(), control));
                frame.result_tx.send(Ok(())).unwrap();
                if control && text.starts_with("(media") {
                    let cbcl_core::sexpr::SExpr::List(items) = cbcl_parser::parse(&text).unwrap()
                    else {
                        panic!("control")
                    };
                    let req = items
                        .windows(2)
                        .find_map(|p| match (&p[0], &p[1]) {
                            (
                                cbcl_core::sexpr::SExpr::Atom(cbcl_core::sexpr::Atom::Keyword(k)),
                                cbcl_core::sexpr::SExpr::Atom(cbcl_core::sexpr::Atom::Str(v)),
                            ) if k == "req" => Some(v.clone()),
                            _ => None,
                        })
                        .unwrap();
                    let reply = if text.starts_with("(mediaupload") {
                        format!(
                            "(mediaput :req \"{req}\" :upload \"0123456789abcdef0123456789abcdef\" :url \"{url}/object\" :expires 2000000000)"
                        )
                    } else if text.starts_with("(mediaget") {
                        format!(
                            "(mediaurl :req \"{req}\" :url \"{url}/object\" :expires 2000000000)"
                        )
                    } else {
                        format!("(mediaok :req \"{req}\")")
                    };
                    store
                        .try_route_meta_reply(&agent, MetaReplyDelivery::Reply(reply))
                        .await;
                }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        state.record = Arc::new(DiscoveryRecord {
            addr: listener.local_addr().unwrap(),
            ..(*state.record).clone()
        });
        let client = LocalApiClient::from_discovery(&state.record).unwrap();
        let app = super::super::router(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let uploaded = client.media_upload(&handle, &request(true)).await.unwrap();
        assert_eq!(uploaded.attachment.size, wav().len());
        let listed = client.media_list(&handle).await.unwrap();
        assert_eq!(listed.attachments.len(), 1);
        assert_eq!(listed.attachments[0].thread, uploaded.attachment.thread);
        let downloaded = client
            .media_download(
                &handle,
                &MediaDownloadRequest {
                    thread: uploaded.attachment.thread.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(STANDARD.decode(&downloaded.data).unwrap(), wav());
        let transcript = sent.lock().unwrap().clone();
        assert!(
            transcript
                .iter()
                .any(|(f, c)| f.starts_with("(mediaupload") && *c)
        );
        assert!(
            transcript
                .iter()
                .any(|(f, c)| f.starts_with("(mediacommit") && *c)
        );
        assert!(
            transcript
                .iter()
                .any(|(f, c)| f.starts_with("(mediaget") && *c)
        );
        assert!(
            transcript
                .iter()
                .any(|(f, c)| f.starts_with("(lang sha256-") && !*c)
        );
        // Object storage holds only sealed bytes, and the production streaming
        // reader refuses redirects, oversized bodies, and corrupt ciphertext.
        let stored = media::get(
            &state.media_http,
            &format!("{base}/object"),
            wav().len() + 48,
        )
        .await
        .unwrap();
        assert_ne!(&stored[..wav().len()], wav().as_slice());
        assert!(
            media::get(&state.media_http, &format!("{base}/oversize"), stored.len())
                .await
                .is_err()
        );
        assert!(
            media::get(&state.media_http, &format!("{base}/redirect"), stored.len())
                .await
                .is_err()
        );
        let (objects, who) = state.agents.objects_for(&handle).await.unwrap();
        let file = objects
            .read(who, uploaded.attachment.thread)
            .await
            .unwrap()
            .unwrap();
        let descriptor = Descriptor::parse(file.state["ref"].as_str().unwrap()).unwrap();
        let bad = media::get(&state.media_http, &format!("{base}/corrupt"), stored.len())
            .await
            .unwrap();
        assert!(descriptor.open(&bad).is_err());
        // No descriptor/key is exposed by list or the ordinary recv queue.
        assert!(
            !serde_json::to_string(&listed)
                .unwrap()
                .contains("encryption")
        );
        assert!(matches!(
            state
                .agents
                .recv(&handle, Some(std::time::Duration::from_millis(10)))
                .await,
            Err(AgentError::RecvTimeout)
        ));
        state.agents.close(&handle).await.unwrap();
        relay.abort();
        server.abort();
        storage.kill().await.unwrap();
    }
}

#[cfg(test)]
mod contract_test {
    use super::*;
    #[tokio::test]
    async fn media_file_contract_matches_browser_starter() {
        let objects = crate::objects::runtime::spawn(
            AgentStore::new(crate::daemon::AgentStoreConfig {
                agent_id_prefix: "contract".into(),
                max_messages_per_handle: 8,
                max_bytes_per_handle: 65536,
            }),
            tokio::runtime::Handle::current(),
            None,
        );
        let compiled = objects.check(media::file_definition()).await.unwrap();
        let browser: Value =
            serde_json::from_str(include_str!("../../tests/vectors/media/file-contract.json"))
                .unwrap();
        assert_eq!(compiled.dialect, browser["dialect"]);
        assert_eq!(compiled.cbcl, browser["definition"]);
    }
}
