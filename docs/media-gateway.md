# Live-View Delivery and the Media Gateway

Covers proposal section 9. Browsers do not play RTSP, so something must sit between the
camera and the viewer. This document states what is implemented today, what is only
evaluated, and what has to be decided before a pilot.

## What is implemented now: authenticated JPEG relay

`src/watchtower/api/routers/live.py` delivers the newest decoded frame from the ingestion
worker as an HTTP `multipart/x-mixed-replace` stream of JPEGs.

The workflow is section 9's, in order:

1. Authorized user selects a camera in the dashboard.
2. `POST /api/live/sessions` requests a live-view session.
3. The backend checks the caller's viewing permission for that camera
   (`can_view_camera`, group-scoped). Administrative rights over a camera do not imply the
   right to watch it.
4. The backend reuses the camera's managed stream, or requests one from the supervisor.
5. The client receives a server-issued opaque session token plus JPEG bytes. **Nothing
   else** — no RTSP URL, no host, no port, no username, no password.
6. The player renders frames and reports loading / live / reconnecting / offline.
7. Closing the player releases the session; the relay also detaches when the HTTP
   connection drops (`request.is_disconnected()`), so a crashed tab does not hold a slot.
8. `DELETE /api/live/sessions/{token}` releases explicitly.

Two properties worth naming because they are easy to get wrong:

- **One source stream, many viewers.** `attach_viewer` / `detach_viewer` are called on the
  actual MJPEG connection, not on session creation, so the viewer count reflects real
  consumers and N viewers never open N RTSP connections to the camera.
- **Session tokens are per-user.** The relay and the snapshot endpoint both reject a token
  presented by someone other than the user it was issued to.

Endpoints: `/sessions` (open), `/sessions/{token}/mjpeg` (relay),
`/sessions/{token}/snapshot` (single current JPEG), `/sessions/{token}/state` (health for
the UI), `/sessions/{token}` DELETE (release).

### What the relay is not

It is not a low-latency interactive transport and it is not a general-purpose streaming
solution. There is no audio, no adaptive bitrate, and per-viewer cost is one JPEG encode
plus bandwidth. `WATCHTOWER_LIVE_MAX_MBPS` bounds egress per stream and
`WATCHTOWER_LIVE_JPEG_QUALITY` sets encode quality.

Use it for: confirming a camera works, the live-view grid, quick visual triage.
Do not use it for: operator-grade wall displays or anything with audio.

## What is preferred for deployment: WebRTC

Section 9 names WebRTC as the preferred interactive transport, with HLS where extra
playback latency is acceptable. That preference has **not** been implemented here, and it
should not be implemented inside the Python process.

The practical route is a media gateway that ingests RTSP once and republishes:

| Transport | Typical latency | Browser support | Cost |
|---|---|---|---|
| MJPEG relay (implemented) | 0.2-1 s per frame | universal | CPU per frame, per-viewer bandwidth |
| WebRTC (via gateway) | sub-second | universal | gateway process, signalling path |
| LL-HLS (via gateway) | 2-10 s | universal (HLS.js on non-Safari) | segment storage, higher latency |
| Low-latency HLS | ~2 s | needs support in packager | more moving parts |

### MediaMTX

The documented evaluation target is MediaMTX: a single Go binary that pulls RTSP and
republishes as WebRTC, HLS and Low-Latency HLS. It is the shortest path to section 9's
preferred transport without writing a media server.

The integration that preserves the security properties is **not** "point the browser at
MediaMTX". It is:

1. The Python ingestion service remains the only component that knows camera credentials.
   It pulls RTSP using the sealed secret, in-process, exactly as today.
2. It hands the stream to the gateway over a localhost or isolated-network publication —
   never a credential the gateway can leak to a client.
3. The application issues a short-lived, per-session, per-camera viewing token, and the
   gateway validates it (shared secret, signed URL, or an auth callback to the backend)
   before serving a single frame.
4. The browser negotiates WebRTC with the gateway, and the ICE/TURN configuration stays
   inside the isolated network.

If step 3 is skipped, the gateway becomes an unauthenticated camera viewer on the network
— which is strictly worse than the current relay, because the relay at least enforces
`can_view_camera` on every frame.

### Decision to record before the pilot

- [ ] Which transport, per use case (grid vs single-camera interactive).
- [ ] Gateway host, version, and which network segment it listens on.
- [ ] Authentication mechanism between backend and gateway, and token lifetime.
- [ ] Whether WebRTC goes peer-to-peer only, or requires TURN. TURN on a public network is
      how a closed-camera system ends up reachable from outside; keep it internal.
- [ ] Audio policy. If cameras carry audio, that is a separate institutional decision about
      recording conversations, not a checkbox in a media server config.
- [ ] Capacity per camera: managed source stream plus N gateway sessions.

None of these can be answered by the code. They are AFIT infrastructure decisions.

## Recording

Recording is deliberately not part of the relay. Evidence is snapshots and clips produced
through `services/evidence.py`, with SHA-256 integrity, access rules and retention — see
section 12 and `docs/detection-limitations.md`. Continuous recording to disk is a gateway
or NVR function; if the institution wants it, decide where it lives, how long it is kept,
and who may retrieve it **before** enabling it, because a retention rule applied
retroactively to a week of accumulated video is not a rule, it is a liability.
