# Browser Powered Session Handler

A Burp Suite extension that runs browser authentication journeys and reuses their
tokens and cookies in HTTP requests. Authentication, caching and request tags are
owned by the Java extension. One universal JAR includes Playwright, Chromium and
its driver; there is no Python service or Hackvertor dependency.

This branch contains the native development build for Windows x64, Linux x64 and
Intel macOS. Apple Silicon and other ARM systems are not supported. See the
[validation record](docs/implementation/universal-packaging-validation.md) for
the exact build and tested environments; native macOS testing remains outstanding.

## Install

1. Use Burp with Java 21 or newer and the Montoya 2026.4 request-drop and Proxy
   action capabilities. Burp 2026.10.1 has been used for interactive checks.
2. Build or obtain `bapp/build/libs/browser-powered-session-handler-dev.jar`
   (about 740 MB). See the validation record for the tested Burp launcher and
   memory settings.
3. In Burp, open **Extensions → Installed → Add**, select **Java**, and choose that JAR.
4. Open the **Browser Powered Session Handler** tab.

On first authentication, bundled browser files are verified and extracted to
`user.home/.bpsh/cache`. Later runs reuse that cache. Runtime setup does not
download a browser or require a separate Java or Node installation.
Only the current system's files are extracted. First use requires additional
temporary disk space; old version caches are retained for rollback. Linux needs
Chromium's system libraries, and visible browsers need a desktop session. The
[developer instructions](bapp/README.md) list these prerequisites and disk usage.

PKCS#11 authentication additionally requires your token vendor's middleware.
[Developer build instructions](bapp/README.md) describe preparation and packaging.

## Create an authentication journey

Choose **Project** or **User** above the journey list, then use **+** to create a
journey. Project journeys belong to the Burp project; User journeys are shared
through your local user library.

Configure the wizard:

1. **Setup:** name, login URL, browser visibility and optional proxy URL.
2. **Login steps:** add browser actions with **+**, then configure their inputs.
3. **Token:** choose JSON response, regex or cookie capture. Several outputs can
   be captured together; give each a token name when there is more than one.
4. **Client certificate:** configure PKCS#11 if the login needs it.
5. **Test & use:** test authentication, inspect its result and use the journey in requests.

Each journey remembers its last displayed step for the current extension session.
Switching Project/User tabs also returns to the last journey opened there.

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
contains request/login timeouts and optional global/per-journey waiting limits.
Durations are in seconds, including fractional seconds. Waiting limits default
to Unlimited.

## Journey cache and event log

Each journey has its own credential cache. **Journey cache**, beside **Event log**,
shows usable cached tokens/cookies and their cache lifetime without starting a
login. Right-click a row for **Copy name** or **Copy value**.

**Event log** shows the selected journey's timestamped authentication and
configuration events. Filter by severity or search messages for the full
explanation of a failure. Event history is kept in memory for the extension
session; credential values, PINs and response bodies are excluded.

Use the cache-clear action in Test & use to invalidate the selected journey.
**Cancel authentication** stops its shared login and releases waiting requests;
it keeps credentials that are still usable.

## Proxy and PKCS#11

An optional explicit HTTP proxy URL can point at a Burp listener. Empty means
direct. Configured proxy authentication is unsupported; use a listener that
does not require credentials. A configured proxy failure does not fall back
to a direct connection.

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
[implementation evidence](docs/implementation/ux-test-matrix.md).

The broader authentication lab and acceptance matrix are integrated under `test/authentication-lab`. Run the selected profiles for current evidence; host, capability and full acceptance gates remain explicit. No release or non-Windows acceptance is implied by the development build.

## Authentication lab

The [Java authentication lab](test/authentication-lab/README.md) provides controlled login applications, protected credential checks, production acceptance profiles and federation fixtures. Run the root Gradle `test` task for native regressions and use the guide for lab commands and prerequisites. Generated runs and reports stay under ignored build directories.
