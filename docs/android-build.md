# Building the Android app

`personnel-app/` is one React + TypeScript + Vite codebase with two delivery targets: a
responsive web app and a native Android app wrapped by Capacitor. The web target is
reachable from any browser and is the faster thing to test. The Android target is what an
officer carries, and it is the only target on which push notifications and deep links from
a lock screen can work.

Nothing in this file has been executed on this machine. **No APK has been produced, no app
has been installed on a handset, and no push token has been registered with a real
Firebase project from here.** The build steps below are derived from the checked-in native
project files, each of which is cited, so the toolchain requirements are facts read out of
the repository rather than guesses. Plan on the first real build surfacing something; the
Troubleshooting section lists the failures this configuration is known to produce.

Related documents: `docs/firebase-setup.md` (the two Firebase artefacts and the package-id
match), `docs/mobile-api-contract.md` (what the app talks to and with which credentials),
`docs/troubleshooting.md`.

## 1. What the native project requires

Read from the files themselves:

| Requirement | Value | Where it is set |
| --- | --- | --- |
| Capacitor | 8.6.0 (`@capacitor/core`, `@capacitor/android`) | `personnel-app/package.json` |
| Push plugin | `@capacitor/push-notifications` 8.1.3 | `personnel-app/package.json` |
| Gradle | 8.14.3 (`gradle-8.14.3-all.zip`) | `android/gradle/wrapper/gradle-wrapper.properties` |
| Android Gradle Plugin | 8.13.0 | `android/build.gradle` |
| Google services plugin | 4.4.4 | `android/build.gradle` |
| Java | 21 (`sourceCompatibility`/`targetCompatibility` `JavaVersion.VERSION_21`) | `android/app/capacitor.build.gradle` |
| Minimum Android | API 24 (Android 7.0) | `android/variables.gradle` `minSdkVersion` |
| Compile / target SDK | 36 / 36 | `android/variables.gradle` |
| Application id | `com.afit.watchtower.personnel` | `capacitor.config.ts`, `android/app/build.gradle` |

So a build machine needs Node.js, JDK 21, and an Android SDK with platform 36 installed.
Android Studio installs the SDK and the matching JDK together and is the least confusing
way to get both; the command line alone works once `ANDROID_HOME` points at an SDK whose
`platforms/` contains `android-36` and whose `build-tools/` is new enough for AGP 8.13.

`minSdkVersion = 24` means older handsets are refused at install time. That is a floor for
the app, not a statement that AFIT handsets are old: it just means nothing below Android 7
needs testing.

## 2. The Android folder is generated — treat it that way

`cap add android` and `npx cap sync android` write files under `android/` from
`capacitor.config.ts` and from the installed plugins. Two consequences:

- The WebView content is copied from `dist/`. `cap:sync` copies what is already there, so
  a stale `dist/` ships a stale app with no warning. Always build first.
- Edit `capacitor.config.ts` and `src/`, not `android/`, except for the four things that
  genuinely live in the native project: `AndroidManifest.xml`, `app/build.gradle`,
  `google-services.json`, and the signing configuration.

## 3. Build steps

From `personnel-app/` (Windows: `cmd` or PowerShell; the npm scripts are the same either way):

```bat
cd personnel-app
npm install
npm run verify
```

`npm run build` is `tsc --noEmit && vite build` - it fails before producing a bundle if any
type is wrong. `npm run verify` runs the build, then `verify:fixtures`, then `verify:api-config`,
then the unit tests.

`verify:fixtures` scans the emitted files and fails if a development fixture is in the bundle. Do
not skip it: a fixture that reaches a release bundle talks to a fake API and still renders a
normal-looking screen.

`verify:api-config` checks the endpoint. It classifies what the production configuration resolves
to - a loopback address, a private LAN address, plain HTTP or a public HTTPS host - and then looks
for the development address inside the emitted JavaScript. This is the check that would have caught
the 2026-11 defect where a handset was shipped configured with the developer's laptop as its server
because Vite reads `.env.local` in every mode, including the one that produces an APK. Read
section 3a before building for anyone outside this machine.

### 3a. Which configuration file says what

`.env.local` is deliberately **not** used by this app. Use the mode-qualified files:

| File | Read by | Holds |
| --- | --- | --- |
| `.env.development` | `npm run dev` | tracked defaults: fixtures on, no API host |
| `.env.production` | `npm run build` | tracked defaults: fixtures off, **no API host** |
| `.env.development.local` | `npm run dev` only | this machine's cloud API, e.g. `http://127.0.0.1:8080` |
| `.env.production.local` | `npm run build` only | the deployed HTTPS endpoint - the file a release build needs |

The two `.local` files are gitignored. A release build with none of them set compiles, boots, and
refuses to sign anybody in with the sentence "No server configured" - which is the correct output for
a backend that has not been deployed, and is what stops a guessed address reaching a phone.

So, for a build that is going onto a handset:

```bat
echo VITE_API_BASE_URL=https://the-deployed-cloud-host> .env.production.local
npm run verify
npm run verify:api-config -- --release
```

`--release` makes an unconfigured endpoint a failure instead of a warning. It is the flag to use when
cutting an APK; leave it off when you are only checking the code.

If a previous build carried a different endpoint, clear the native build cache before assembling, or
Gradle can merge a stale copy of the old bundle into the APK:

```bat
cd android && gradlew.bat clean
```

Then, after any change to `src/`, config, or a plugin install:

```bat
npm run cap:sync
```

If `android/` is not present yet (it is checked in, so normally it is), `npm run cap:add:android`
generates it from `capacitor.config.ts`.

Open in Android Studio (this is also where signing and the SDK manager are easiest):

```bat
npm run android:open
```

Build a debug APK from the command line - `npm run android:apk` runs
`cd android && gradlew.bat assembleDebug`:

```bat
npm run android:apk
```

The output is `android/app/build/outputs/apk/debug/app-debug.apk`. Install it on a handset
with USB debugging enabled (Android Studio's device bar, `adb install`, or copying the APK
and opening it - the last of those requires allowing installs from unknown sources, which
is fine for a pilot handset and not something to write down as normal practice).

### Debug versus release

`android/app/build.gradle` declares no `signingConfig` for the `release` build type. So
`assembleRelease` produces an **unsigned** release APK, which no handset will install.
Before any distribution beyond a debug build, a keystore has to be created and wired in:

```bat
keytool -genkeypair -v -keystore watchtower-personnel.keystore -alias watchtower-personnel -keyalg RSA -keysize 2048 -validity 10000
```

and then referenced from a `signingConfigs` block that reads its password from the
environment or from a file outside source control. The keystore is a credential: losing it
means not being able to publish an update signed the same way, and committing it means
anyone can publish updates as this app. Neither belongs in the repository.

## 4. What must be configured before the app is useful

| Thing | Why the build needs it | Where |
| --- | --- | --- |
| `VITE_API_URL` or `VITE_API_BASE_URL` | The deployed cloud endpoint. The app has **no default host**: with neither set it boots into "No server configured" and the login button is disabled, so nothing is ever sent to a guessed address. Must be HTTPS on a host a phone can resolve; a loopback or LAN address in a release build is refused by `src/config/apiUrl.ts` and flagged by `verify:api-config`. | `personnel-app/.env.production.local` (gitignored), or the build environment |
| `VITE_FIREBASE_*` (6 keys) | Web push / Firebase initialisation on the web target. Public client config only - see the hard rules in `.env.example`. | same |
| `android/app/google-services.json` | Native FCM. Its absence is **not** a build failure: `app/build.gradle` applies the google-services plugin only if the file exists, and logs "Push Notifications won't work". | from the Firebase Console |
| The API host in `AndroidManifest.xml` | The HTTPS deep-link filter still carries the placeholder `watchtower-api.example.invalid`. | see §5 |
| Personnel accounts | An officer cannot self-register; they exist because the monitoring side or an administrator created them. | `docs/installation.md` |

The Firebase entries are explained properly in `docs/firebase-setup.md`, including the
third item's trap: the build succeeds, the app runs, registration returns a token, and the
cloud silently cannot deliver - because delivery depends on the service account and project
id on the *server*, not on this file.

## 5. Deep links: one edit is required before release

The manifest registers two ways to open an incident:

- `watchtower://incidents/<id>` — the custom scheme. Nothing to configure. It is fixed at
  `watchtower://` and is deliberately not an environment variable, because the server puts
  this value into push payloads; a configurable scheme would let a deployment disagree with
  what the cloud sends.
- `https://<host>/incidents/<id>` under `android:autoVerify="true"` — the App Links form.
  `autoVerify` makes Android ask that host for `/.well-known/assetlinks.json` and only
  route the link to the app if the file lists this package id and signing certificate.
  The checked-in host is `watchtower-api.example.invalid`.

With the placeholder left in place the custom scheme still works; the HTTPS link opens in a
browser instead of the app. To make App Links work you must replace the `<data android:host=…/>`
value with the real API host **and** serve `/.well-known/assetlinks.json` from it
containing the fingerprint of the certificate that actually signed the distributed APK.
Generating that file is Android Studio's *App Links* tool or:

```bat
keytool -list -v -keystore watchtower-personnel.keystore
```

The SHA-256 in that output is the `current_fingerprints` value. Because it depends on the
release certificate, an App Link verified for a debug build is not verified for a release
build.

## 6. Permissions and notification channels

Declared in `android/app/src/main/AndroidManifest.xml`: `INTERNET`, `POST_NOTIFICATIONS`,
`VIBRATE`. `POST_NOTIFICATIONS` is the Android 13+ (API 33) runtime permission; without it
a correctly delivered push updates the app's data and shows nothing. The app requests it
through `PushNotifications.requestPermissions()` in `src/push/pushRuntime.ts`, and an
officer who denies it is told in the app's notification-settings screen rather than being
re-prompted.

The five Android notification channels are created at runtime by `pushRuntime.ts`, one per
band: `watchtower-critical` (the manifest default), `watchtower-high`, `watchtower-warning`,
`watchtower-informational`, `watchtower-camera-health`. Two consequences worth knowing when
an alert "did not arrive":

- Android discards a notification whose `channel_id` does not exist on the handset. The
  server must name a channel the app actually creates, and there is a test in the Python
  suite that reads `src/lib/severity.ts` to keep the two lists from drifting
  (`tests/test_cloud_delivery.py`, `TestAndroidPresentation`).
- A channel's sound, vibration and importance are owned by the handset once the channel
  exists - an app cannot rewrite them per message, and neither can the server. So the
  profile's `sound` preference is honoured as "this push arrives on a silent channel or not"
  (`docs/mobile-api-contract.md` §10.6), and the actual tone is changed on the phone under
  Settings → Apps → AFIT WATCH TOWER → Notifications.

## 7. The web target

```bat
npm run build
npm run preview
```

`preview` serves `dist/` on loopback. Web push requires HTTPS *or* loopback plus a Firebase
web configuration; on a LAN IP over plain HTTP, the app works and push does not register.
The web target is the right place to check screens, tables and the evidence viewer. It is
not a substitute for the Android target when the thing being tested is a notification from
a lock screen.

## 8. What has and has not been proven here

Proven by automated checks that run on this machine:

- `npm run verify` green: typecheck, Vite build, fixture-scan of the emitted bundle,
  `verify:api-config` (the production endpoint classified, and this machine's development address
  searched for inside the emitted JavaScript), and the unit suite (125 tests across 12 files)
  covering the API client, token refresh queue, endpoint classification, deep-link parser, fixture
  transport, and screen logic.
- That a production bundle built on this machine contains no loopback address. It was verified by
  rebuilding after the configuration split and scanning the output; the bundle that shipped to the
  handset in November 2026 did contain one, which is the defect section 3a exists to prevent.
- The native project's declared toolchain, permissions, intent filters and plugin wiring
  are internally consistent, and the push payload the server sends matches the channels the
  app creates (the drift guard above).

Not proven, and still requiring a person with a handset and a deployed cloud service:

- That a **correctly configured** build installs and signs in on a device. What has happened is the
  opposite kind of test: `gradlew.bat assembleDebug` completed on this machine on 2026-11-03 and the
  resulting APK was installed on the owner's handset, where sign-in failed with "cannot reach the
  service" because the bundle carried `http://127.0.0.1:8080`. That is the defect section 3a and
  `verify:api-config` were written for. The fix is verified on the build machine, not on the phone —
  no APK rebuilt after it has been installed yet, because there is no HTTPS cloud host for it to
  point at.
- That the splash screen and WebView behave on a device beyond what that install showed, that the
  `POST_NOTIFICATIONS` prompt appears, or that a notification from each channel is visible.
- Acceptance Tests 2, 4, 5 and 8 of `docs/testing.md` §"Mobile acceptance" (device
  registration with a real FCM token, an alert reaching a phone, tapping it, and delivery
  outside the AFIT network). These need a Firebase project, a signed-in build, and a
  handset. No documentation, test, or code in this repository makes them pass in advance.
