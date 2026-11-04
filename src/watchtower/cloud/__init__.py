"""AFIT WATCH TOWER personnel-mobile cloud service.

This is the host-facing half of the mobile system: the only thing a phone is ever allowed to
reach. It reads and writes the same Neon database as the monitoring application - one incident,
one record, one owner - and it is the only component that talks to Firebase Cloud Messaging.

What it deliberately is not:

  * It does not touch RTSP. No endpoint here can return a camera URL, a camera credential or a
    row of `camera_secrets`; the phone sees the camera's display name and nothing else.
  * It does not serve live video. Live view stays on the console inside the AFIT network.
  * It does not trust the monitoring host's identity to anything but an HMAC signature, and it
    does not trust a phone's identity to anything but a short-lived bearer token.

The process is separate from `watchtower.api.app`, so a phone flood cannot starve the
supervision loop of connections. Both processes may run on one host for a pilot.
"""
