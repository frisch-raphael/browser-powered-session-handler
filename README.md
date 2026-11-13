# Browser Powered Session Handler

A Burp Suite extension that runs browser authentication journeys and reuses their
tokens and cookies in HTTP requests. Authentication, caching and request tags are
owned by the Java extension. One universal JAR includes Playwright and its platform drivers; there is no Python service or Hackvertor dependency.

This branch contains the native development build for Windows x64, Linux x64 and
Intel macOS. Apple Silicon and other ARM systems are not supported. See the
[packaging design](docs/designs/universal-packaging.md) for
the payload layout and platform contract; native macOS testing remains outstanding.

## Install

1. Use Burp with Java 21 or newer and the Montoya 2026.4 request-drop and Proxy
   action capabilities. Burp 2026.10.1 has been used for interactive checks.
2. Build or obtain `bapp/build/libs/browser-powered-session-handler-dev.jar`
   (below 128 MiB). Install Burp Browser through Burp before using browser login or recording.
3. In Burp, open **Extensions → Installed → Add**, select **Java**, and choose that JAR.
4. Open the **Browser Powered Session Handler** tab.

Login and recording launch the installed Burp Browser in separate temporary
sessions. Existing Burp browser accounts, cookies and profiles are never adopted
or cleared. There is no bundled or downloaded browser fallback.

Automatic discovery uses the running Burp installation when identifiable. If
several installations are found, open **Settings > Burp Browser** and select the
intended executable. Automatic detection displays the resolved executable path
without saving a custom selection. Editing the path or using **Browse** selects a
custom executable; **Restore automatic detection** clears that selection and is
disabled while already automatic. The selection is local to your Burp user preferences and is absent
from journey exports. A missing or invalid browser is reported beside this setting.

On first authentication, bundled Node/driver files are verified and extracted to
`user.home/.bpsh/cache/drivers-v3`. Later attempts reuse that verified cache.
Runtime setup requires no separate Java or Node installation and downloads
nothing. Linux needs the installed browser's shared libraries and sandbox
permissions; visible recording needs a desktop. The
[developer instructions](bapp/README.md) describe prerequisites and disk usage.

PKCS#11 authentication additionally requires your token vendor's middleware.
[Developer build instructions](bapp/README.md) describe preparation and packaging.

## Create an authentication journey

Choose **Project** or **User** above the journey list, then use **+** to create a
journey. Project journeys belong to the Burp project; User journeys are shared
through your local user library.

Configure the wizard:

1. **Setup:** name, login URL, authentication methods, browser visibility and optional proxy URL.
   Combine form-based, PKCS#11 client-certificate and HTTP authentication as needed.
2. **Login steps:** shown when **Use form-based authentication** is checked. Add browser actions with **+**, then configure their inputs. Turning the method off retains the steps and skips their execution.
3. **Capture credentials:** choose JSON response, regex or cookie capture. This page stays available for every authentication method. Several outputs can
   be captured together; give each a token name when there is more than one.
4. **Client certificate:** configure PKCS#11 if the login needs it.
5. **Test & use:** shown when at least one authentication method is checked. Test authentication, inspect its result and use the journey in requests.

Each journey remembers its last displayed step for the current extension session.
Switching Project/User tabs also returns to the last journey opened there.

To reuse a journey's configuration, select it and choose **Duplicate selected**
from the **...** menu above the list. The copy opens in the same collection with
a unique name and tag. Configured secrets are copied for this session, with
**Remember secrets** off; cached tokens, cookies and Session handling rules are
not copied.

The request-tag alias is derived from the journey name: **Employee login**
becomes `<@employee-login/>`. Renaming a journey updates its alias when saved;
update existing request tags afterward. Copy BPSH tag and the request context menu provide the actual reference.
Conflicting aliases must be repaired before the journeys can execute.

Journey edits autosave after 500 ms, including unfinished settings. **Ctrl+S** flushes or retries autosave. **Test login** flushes edits and reports configuration errors before starting authentication.
**Remember secrets** stores PINs and secure step inputs as readable local data.
Leave it off to keep those values for the current extension session.

## Use request tags

In an editable request, right-click **Add authentication token**, then choose a
journey, a named output when needed, and its encoding.

A single-output journey:

```http
Authorization: Bearer <@employee-login/>
```

Several outputs from one journey:

```http
Authorization: Bearer <@employee-login token="access"/>
Cookie: session=<@employee-login token="session"/>
```

Tags can appear in headers, text bodies, URL paths and query parameters. Values
are raw by default; use a wrapper where encoding is required:

| Wrapper | Result |
| --- | --- |
| `<@url><@employee-login/></@url>` | URL-component encoding |
| `<@form><@employee-login/></@form>` | Form encoding |
| `<@json><@employee-login/></@json>` | JSON string content, without surrounding quotes |

Tags are processed regardless of Session handling's enable switch, selected
tools or URL scope. A request containing explicit tags uses those tags instead
of automatic injection. A tag failure stops the request and logs corrective
guidance. There is no tag namespace prefix or separate custom-tag installation.

## Session handling

Enable **Session handling** to add credentials automatically to matching
requests. Add saved journeys to the ordered list and set each rule's URL scope
and session-expiration detection. Matching journeys run from top to bottom,
reusing valid cached sessions. The last matching value wins when destinations
overlap.

For each JSON or regex output, choose Disabled, Bearer, Header or Cookie as its
injection destination. Captured cookies use their original cookie names.
All required journeys must succeed before credentials are applied. If ordinary
automatic authentication fails, the original request goes through with a warning.

Expiration detection can use an HTTP status, a response-text RE2 expression, or
either condition. With Session handling enabled, an attributed session loss can trigger recovery and replay each original application request at most once. A rejected replacement pauses automatic recovery until an explicit Test login.

Valid Session handling and waiting-limit edits save automatically. **Settings**
contains request/login timeouts and finite global/per-journey request limits.
Durations are in seconds, including fractional seconds. Request limits default
to 64 globally and 16 per journey, including direct HTTP authentication. Excess
automatic requests continue unchanged with a diagnostic; explicit tagged requests
are stopped. Send immediately starts login in the background without waiting.

Automatic token/cookie insertion processes the headers separately and preserves
upload bodies as host byte arrays. Request preparation has a shared 512 MiB copy
budget, conservatively reserving four times the message size plus 16 MiB for header
expansion before processing.
An individual automatic request above 124 MiB therefore continues unchanged with
a capacity diagnostic. Tagged/direct HTTP-auth messages retain their 4 MiB limit.
Recovery retains a template only when detection is enabled and the original fits
its 4 MiB individual / 32 MiB aggregate budget; otherwise login recovery can run,
but resending the original request is manual.

## Journey cache and event log

Each journey has its own credential cache. **Journey cache**, beside **Event log**,
shows usable cached tokens/cookies and their cache lifetime without starting a
login. Right-click a row for **Copy name** or **Copy value**.

HTTP authentication also appears here, including HTTP-only journeys: protocol,
account, exact server origin, latest progress/result and observation time. These
rows contain no password or reusable NTLM response and have no credential-copy
actions. Clear cache removes the observed result; the saved identity remains.

**Event log** shows the selected journey's timestamped authentication and
configuration events. Filter by severity or search messages for the full
explanation of a failure. Event history is kept in memory for the extension
session; credential values, PINs and response bodies are excluded.

HTTP authentication logs NTLM negotiate, validated challenge and authentication
response steps, server acceptance, connection reuse, and actionable failures.
This covers browser login, recording, HTTP-only tests and tagged requests.

Use the cache-clear action in Test & use to invalidate the selected journey.
**Cancel authentication** stops its shared login and releases waiting requests;
it keeps credentials that are still usable.

## Proxy and PKCS#11

Chromium sandboxing is required for login and recording. On Linux, allow the
user namespaces needed by Chromium and install the documented browser libraries.
The installed sandbox helper must have the ownership and permissions required by
Chromium; BPSH reports a confirmed helper configuration failure with administrator guidance.
For this specific failure, an administrator can set the `chrome-sandbox` file next
to the selected executable to owner `root:root` and mode `4755`, as documented in
[PortSwigger's Linux troubleshooting guidance](https://portswigger.net/burp/documentation/dast/user-guide/reference/browser-powered).
Recheck after Burp Browser updates, which may install a new version-specific helper.
BPSH does not change these permissions automatically.

For a test website or proxy certificate that Chromium does not trust, enable **Allow untrusted HTTPS certificates** in the journey's **Setup**. It applies to that journey's recording and login only and defaults to off. Client-certificate journeys retain their separate server-trust checks and Trusted CA setting.

The journey's optional HTTP proxy URL applies to browser login, recording and
Basic/NTLM delivery, and can point at a Burp listener. Empty means direct.
These authentication paths do not inherit Burp's global upstream-proxy settings. Configured proxy authentication is unsupported; use a listener that
does not require credentials. A configured proxy failure does not fall back
to a direct connection.

PKCS#11 middleware and private-key signing run in an owned helper process using
Burp's Java runtime. Unloading terminates the helper; private keys stay on the
device. Rejected or indeterminate PIN outcomes still require an explicit Retry.

For a client-certificate journey, select the middleware file. Connected initialized
tokens are discovered without a PIN. A sole device is selected automatically;
if several are available, choose a named device from the inline dropdown. The
PIN, Choose certificate and advanced settings then appear. Certificate details
appear only after a certificate is chosen. The device identifier is saved automatically; there are
no manual slot fields. The HTTPS Login URL's server is included
automatically. Advanced settings contain additional authentication servers and
an optional Trusted CA file. An HTTP Login URL needs an explicitly configured
HTTPS authentication server. Certificates
with identical subjects are distinguished by their fingerprints. Java uses the
vendor middleware through PKCS#11; only these journeys create the local TLS
proxy. A Firefox certificate profile is not needed. PKCS#12 is outside the
current scope.

## Storage and transfer

Use the journey **…** menu to import, export or delete selected journeys.
Ctrl/Shift selects several journeys. Import accepts multiple files and previews
the selected entries before writing them.

The native project key is `bpsh_project_v3`. The User library is
`user.home/.bpsh/library-v3.json`. Native exports include secrets only when
explicitly selected; cached credentials, browser state and private keys are
excluded.

## Development status

See [build and architecture guidance](bapp/README.md) and
[interface contract](docs/designs/interface.md).

The broader authentication lab and acceptance matrix are integrated under `test/authentication-lab`. Run the selected profiles for current evidence; host, capability and full acceptance gates remain explicit. No release or non-Windows acceptance is implied by the development build.

## Authentication lab

The [Java authentication lab](test/authentication-lab/README.md) provides controlled login applications, protected credential checks, production acceptance profiles and federation fixtures. Run the root Gradle `test` task for native regressions and use the guide for lab commands and prerequisites. Generated runs and reports stay under ignored build directories.

## System Overview

The Java extension composes a shared service graph in `Extension.initialize`; authentication attempts borrow the browser/native services while HTTP hooks acquire and insert credentials through the coordinator. The lab applications provide controlled verification boundaries.

## Subdirectories & System Boundaries

- [bapp](./bapp/README.md): production Montoya extension, build and package contracts.
- [test](./test/README.md): controlled Java applications and disposable native fixture tooling.
- [docs](./docs/README.md): maintained product and design documents.

## Interface

The runtime entry point is [Extension.java:Extension.initialize](./bapp/src/main/java/bpsh/Extension.java). Developer and verification interfaces are indexed in the child contracts above.

## Global Invariants

- [Extension.java:Extension.supported](./bapp/src/main/java/bpsh/Extension.java) checks Java and Montoya capabilities before enabling authentication hooks.
- [architecture.gradle.kts:verifyArchitecture](./bapp/gradle/architecture.gradle.kts) enforces the production feature dependency graph.

## Global Side Effects

[Extension.java:Extension.initialize and Services.close](./bapp/src/main/java/bpsh/Extension.java) own host registrations and resource cleanup. Child contracts describe project/user storage, browser extraction, network authentication and native middleware ownership.

## System Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser, native middleware and host acceptance require their explicit tasks and prerequisites; see [bapp](./bapp/README.md) and [the lab](./test/authentication-lab/README.md).
