# Firebase setup (push delivery)

Everything in this file is a **manual step in the Firebase console**. None of it can be done from
this repository, and until it is done, push notifications do not reach a phone. The service says so
rather than pretending: with no Firebase project configured, every send is recorded as
`not_configured` and the cloud's own status output reports push as off
(`src/watchtower/cloud/push.py`, `DisabledSender`).

No part of this setup requires Cloud Functions, a Firebase database, or a server key. The cloud
service talks to FCM's HTTP v1 endpoint itself.

---

## 1. What each credential is for

There are **two different Firebase artefacts**, and putting the wrong one in the wrong place is the
most common way this breaks.

| Artefact | Where it goes | Secret? |
|---|---|---|
| `google-services.json` | `personnel-app/android/app/` | Client-side. Identifies the Android app to Firebase. Contains an API key that is public by design. |
| Service account JSON | a path on the **cloud server**, named by `CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE` | **Private.** Contains a 2048-bit RSA private key that can send push to every device in the project. |

The private key must never be placed inside `personnel-app`, never committed, and never printed. It
is read once at process start by `_read_service_account()`
(`src/watchtower/cloud/push.py:302`), used only to sign an OAuth2 assertion, and is deliberately
kept out of logs, exception text and API responses (`redact()` is applied to everything that leaves
the module).

---

## 2. Create the project and the Android app

1. console.firebase.google.com → **Add project**. No Analytics needed; no Firebase database is used.
2. Inside the project → **Project settings → Your apps → Add app → Android**.
3. **Android package name**: `com.afit.watchtower.personnel`.
   This string must match all three of:
   - `appId` in `personnel-app/capacitor.config.ts`,
   - `applicationId` in `personnel-app/android/app/build.gradle`,
   - the `package_name` Firebase puts in `google-services.json`.

   A mismatch is not a build error. The handset registers a token against one Firebase app, the
   cloud sends to the project the token belongs to, and delivery fails with no useful message.
   Treat this as the first thing to check if a phone never receives anything.
4. Download `google-services.json` and put it at `personnel-app/android/app/google-services.json`.
5. **Add the `firebase-messaging` service to the project.** In Project settings → Cloud Messaging,
   confirm "Firebase Cloud Messaging" is enabled for the project (it is by default for a new
   project with no legacy credentials). Note the **Project ID** and the
   **Sender ID** — the project id is what the FCM v1 URL is built from
   (`src/watchtower/cloud/push.py:82`).

---

## 3. The service account the cloud server uses

1. Google Cloud console (same project) → **IAM & Admin → Service accounts → Create service
   account**. Name it something obvious, e.g. `watchtower-push`. Do not grant it any other access.
2. On the new account → **Keys → Add key → JSON**. Google downloads one file containing
   `client_email`, `private_key` and `token_uri`. Those three are exactly what this code reads.
3. Grant the account the role that allows sending FCM messages — the permission
   `firebase.messaging.requests.create`. In the console this is the "Firebase Cloud Messaging"
   admin role for the project. If a send later fails with `PERMISSION_DENIED` or
   `sender-id-permission-denied`, this grant is the cause, and the code reports it as a delivery
   failure rather than retrying it.
4. Copy the downloaded file to the cloud server **outside** any directory that is served, built or
   synced. A conventional place is the same directory as the cloud `.env`, with mode `0600`:

   ```bash
   sudo install -m 600 -o watchtower ~/Downloads/watchtower-push-1a2b3c4d5e.json \
     /etc/watchtower/firebase-service-account.json
   ```

   On Windows, put it under the project's `var/` directory — which is git-ignored — and keep the
   ACL as tight as the account running the service requires.

5. Never put this file in the repository. `.gitignore` already excludes `var/`, and the file must
   not be given any other name that suggests it is shareable.

---

## 4. Configure the cloud service

Two variables, and they come as a pair — setting one without the other is a startup error rather
than a silent fallback (`src/watchtower/cloud/config.py:202`):

```ini
CLOUD_FIREBASE_PROJECT_ID=<the project id from step 2.5>
CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE=/etc/watchtower/firebase-service-account.json
```

Then ask the service whether it believes it can deliver:

```bash
cd watchtower
PYTHONPATH=src python -m watchtower.cloud --env-file .env verify
```

(`verify` is the subcommand; there is no `config-check`. With `CLOUD_DATABASE_URL` absent the
command exits 2 with `configuration error: CLOUD_DATABASE_URL is required…` rather than
printing a partial report.)

The lines that matter (`src/watchtower/cloud/cli.py:226`):

- `[ok] Firebase service account: <the path>` — both variables set and the file readable.
- `[!!] push delivery: not configured`, with the note "alerts are recorded as failed with
  notification_attempts.error_code=not_configured instead of paging" — both variables absent.
  Nothing is sent; **this is the expected state before you have done this setup**, and the
  console keeps working.
- a blocking item, "the Firebase service account file is configured but not readable", and a
  startup refusal if the path does not exist at all. This is deliberate: a configured-but-broken
  credential is reported, not quietly downgraded.

Verified against this repository on 2026-11-02, with no Firebase configuration at all, the
command reports `[!!] push delivery: not configured` and still ends `Ready to serve.` — push is
an optional capability, not a boot requirement.

Restart the service after changing them.

---

## 5. Configure the app

`personnel-app/android/app/google-services.json` (step 2.4) is the only Firebase file the app
needs; the Capacitor build picks it up automatically. The optional
`VITE_FIREBASE_*` values in `personnel-app/.env.example` are the public web client config and are
not required for Android push — leave them empty unless you also run the web build.

**No `google-services.json` is not a build failure.** `android/app/build.gradle:47` applies the
Google Services plugin only when the file exists, so the APK still builds and runs — and push
registration then fails with `registrationError`, whose text the app shows verbatim instead of
displaying a fake "notifications enabled" state.

**What an officer still gets without Firebase:** the dashboard, the alert centre and the incident
history re-read themselves every `VITE_ALERT_POLL_SECONDS` while the app is in the foreground, so an
alert raised at the monitoring host appears on a phone that is open and signed in, with no Google
project involved - and while that connection is healthy, an open app also holds the live channel of
§10.8, which shortens the same thing from about twenty seconds to about two. Both are pulls or
near-real-time reads of the same rows; neither is a push. The cadence and its limits are in §10.7 of
`docs/mobile-api-contract.md`, the live channel's in §10.8, and a phone whose app is closed receives
nothing until it is opened again - **no configuration, including `VITE_LIVE_FEED`, changes that**. Nothing in that list is a reason to skip the setup below — an alert nobody is looking at is
not an alert.

---

## 6. What is verified and what is not

Verified by the test suite: the FCM request body this service builds, the OAuth2 assertion it
signs, the retry rules it applies to Google's answers, the device-token lifecycle, and the fact
that a host with no credentials reports `not_configured`.

**Not verified — no test has contacted Google or a real handset.** Delivery to an actual device
requires the setup above plus a physical Android device running the built APK. Acceptance tests 2,
4 and 8 in the proposal ("obtains an FCM token", "an authorized phone receives a push", "receives a
notification outside the AFIT network") remain open until that run is done. See
`docs/testing.md`.
