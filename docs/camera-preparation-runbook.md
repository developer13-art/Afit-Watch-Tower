# Camera Preparation and RTSP Enablement Runbook

Covers proposal section 6.4. This document describes work that happens **outside** the
application, on physical equipment, and it is the only part of the project that requires
authorization from the relevant AFIT authority before it can be carried out.

Nothing in this runbook has been executed by the prototype. Step 1 through step 7 must be
performed by an authorized technician on each camera; only then does step 8 (registration)
become possible.

## What this runbook does not assume

The proposal is explicit and the software enforces the same limits:

- **RTSP cannot be enabled remotely by the application.** The system has no camera
  provisioning capability. It connects to a stream that a human has already enabled and
  verified.
- **No camera is auto-discovered.** There is no ONVIF/WS-Discovery sweep and the codebase
  contains none. Every camera arrives through the registration form.
- **UBox-managed models are not treated as one family.** Configuration differs per model
  and per firmware; a procedure that works on one unit is evidence about that unit only.
- **`ceshi.ini` is camera-specific.** It applies only to the camera whose model and
  firmware were checked and for which its applicability was confirmed. Do not copy the
  file onto another camera because the model number looks similar.
- **The stream path is not a constant.** `rtsp://user:pass@192.168.1.50:554/verify/path`
  in the proposal is a format illustration. A different camera may use a different port,
  a different path, or no authentication at all. Each must be verified in VLC.

## Procedure

### 1. Identify the camera and its network configuration

Record before touching anything: physical location, model, firmware version, current admin
address, whether it is on PoE or a wall adapter, and whether it is already in service for
another system. If the camera is operational, changing its settings is a change to a live
security control and needs sign-off.

### 2. Obtain authorization before changing settings

Get written authorization from the security authority that owns the camera. Note the
scope: which camera, which settings, and how long it may be offline while you work.
Changing a camera on a restricted-zone without that scope is the kind of action this
project's governance section is meant to prevent.

### 3. Apply the approved camera-specific RTSP-enablement procedure

Only if the specific camera requires it. Steps are model-dependent. Where the model uses
the `ceshi.ini` method, apply it exactly as documented for that confirmed model, on the
camera whose applicability was verified. After any change, power-cycle the camera and
re-check its web interface, because some units keep serving the old configuration until
they restart.

### 4. Connect the camera to the authorized network

Use the network the monitoring host will actually reach. A stream verified over a direct
laptop-to-camera link proves less than a stream verified over the intended infrastructure;
VLANs, routing and Wi-Fi client isolation all change the result.

### 5. Identify the camera's actual network address

Confirm the address the camera holds now, and whether it is static or DHCP-assigned. A
DHCP lease that changes tonight turns a working camera into an `offline` one. Prefer a
reservation; if that is not possible, record the lease so the health alert is diagnosable.

### 6. Verify the stream in VLC

This step is the human check that section 6.5 then automates.

1. `Media > Open Network Stream`, paste the full RTSP URL.
2. Confirm video actually decodes — a progress bar alone is not confirmation.
3. Note latency, resolution and frame rate.
4. Try both transport options if VLC exposes them. RTSP-over-UDP can look fine on the
   camera's own network and fail across a router; the application defaults to TCP.
5. Test from the machine that will run the ingestion service, not only from the laptop
   standing next to the camera.

If VLC cannot play it, the application will not play it. Stop here and fix the camera side.

### 7. Record the exact working connection path and authentication requirements

Capture, into the installation record rather than into a chat message: host, port, the
complete stream path including any trailing segment, username, whether authentication was
required at all, transport, resolution and fps. The password goes into the approved
secret-handling channel — not into this record, not into a ticket, not into a screenshot.

Paths are frequently mis-copied by one character. The five most common causes of a failed
connection test are all in this step: wrong path, wrong port, wrong host, disabled RTSP,
and credentials that were changed on the camera after the VLC test.

### 8. Register the camera in AFIT WATCH TOWER

`Camera Management > Add Camera`.

- **Method A** — paste the verified RTSP string. The backend parses it, extracts the
  credentials into a sealed `camera_secrets` row, and discards the credential-bearing URL;
  it is never stored as a single string and never returned to the browser.
- **Method B** — enter host, port, stream path, username and password as separate fields.
  The backend builds the connection profile and percent-encodes special characters in the
  credentials, which is the usual reason a hand-assembled URL fails.

Either method produces the same validated `ConnectionSpec`. Fields are verified before any
network call: protocol must be `rtsp`, port must be in range, a stream path is required.

### 9. Test the connection from the application's intended host

Press **Test Connection**. The ingestion service runs, in order:

| Stage | Checks | Failure reported as |
|---|---|---|
| Reachability | TCP connect to host:port | `host_unreachable`, `timed_out` |
| RTSP handshake | `OPTIONS` then `DESCRIBE` on a raw socket | `authentication_failed` on 401/407, `stream_path_invalid_or_unsupported` on 404/501 |
| Frame decode | Open and decode the configured frame count | `video_decode_failed` |
| Sustain | Hold the stream briefly | `video_decode_failed` / `timed_out` |

A hand-written `DESCRIBE` is used deliberately: it distinguishes "credentials rejected"
from "path does not exist" without relying on a decoder to guess, which is why section
6.5's distinct results are actually reachable rather than cosmetic.

If the test fails, the operator sees the specific stage. Error text is passed through
`redact()`, so no message, log line or audit row can contain a password or a complete
credential-bearing URL.

### 10. Activate the camera after successful verification

Activation is a separate, explicit action after a passed test, and it still does not make
the camera `Online`:

- `services/cameras.py::activate()` raises `test_required` if no test has run and
  `test_not_passed` if the latest test failed. There is no path from "form submitted" to
  "online".
- Activation sets status `testing` and asks the supervisor for a managed session.
- The health evaluator promotes the camera to `online` **only when valid frames are
  arriving**. See section 10 of the proposal and `src/watchtower/health/evaluator.py`.

A camera that connects, then silently stops delivering frames, degrades to `degraded`,
then `reconnecting`, then `offline` — and each transition records a health event distinct
from any AI detection.

## After activation, before the next camera

1. Watch the live view for a few minutes and confirm the frame rate reported in the
   dashboard matches what VLC showed.
2. Cover the lens briefly. If AI monitoring is enabled for that camera, that is the
   cheapest possible sanity check that frames are still flowing.
3. Pull the network cable for longer than `WATCHTOWER_OFFLINE_AFTER_SECONDS` and confirm
   an offline health event and a notification appear, then restore it and confirm recovery.
4. Record the verified parameters in the installation register so the next technician does
   not repeat steps 1-7.

## Escalate rather than improvise

Stop and escalate to the authorizing authority if the camera requires a firmware update,
if enabling RTSP disables another function, if the only reachable address is outside the
authorized network segment, or if the camera is shared with a system this project does not
own. RTSP carries neither video nor credentials encrypted, so any suggestion to expose a
camera address beyond an isolated segment should be treated as a security decision, not a
networking convenience.
