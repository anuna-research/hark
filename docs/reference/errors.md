---
title: Exit and daemon API errors
mode: reference
---

# Exit and daemon API errors

These codes describe command outcomes and loopback API failures.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 2 | usage error or malformed local request |
| 3 | daemon not running |
| 4 | daemon already running for foreground `daemon run` |
| 5 | stale daemon discovery state |
| 6 | no exported handle and no active agent |
| 7 | agent handle is unknown, unhealthy, or busy |
| 8 | CBCL validation or command-kind validation failed |
| 9 | router configuration, connection, or authentication failure |
| 10 | timeout |
| 11 | local daemon authentication failed |
| 12 | daemon API incompatibility or unexpected internal error |
| 13 | retryable agent-not-ready condition |

## Local API error codes

The daemon returns stable JSON errors on its loopback API. Common codes include:

* `missing_daemon_token`, `invalid_daemon_token`
* `daemon_api_incompatible`
* `missing_router_ws_url`, `invalid_router_ws_url`
* `router_auth_rejected` (a proxy 401/403 in front of `/agent/v1`; the hub has no
  connection auth), `router_connection_failed`
* `missing_dialect`, `duplicate_dialect`, `invalid_dialect`
* `malformed_agent_handle`, `unknown_agent_handle`,
  `agent_handle_unhealthy`
* `recv_already_waiting`, `recv_timeout`, `daemon_stopping`, `agent_not_ready`
* `cbcl_validation_failed`, `shape_violation`, `causal_violation`,
  `message_kind_mismatch`, `missing_thread`, `duplicate_thread`,
  `invalid_thread`
* `invalid_subscribe_pattern`, `meta_send_busy`, `meta_reply_timeout`,
  `dialect_unknown_to_router`
* `meta_reply_malformed`, `meta_reply_missing_digest`,
  `meta_reply_missing_name`
* `objects_unsupported` (router transport), `objects_not_subscribed`,
  `objects_unavailable`, `object_unknown`, `object_rejected`,
  `object_action_rejected`
* `malformed_history_request`, `history_in_flight`, `room_not_joined`
* `internal_error`

See [Local daemon API](../../specs/local-api.md) and [CLI UX contract](../../specs/cli.md)
for the detailed contract.
