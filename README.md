# Browser Powered Session Handler

This project provides a Burp Montoya extension (`bapp`) and a Python token service (`api`) to automate authenticated traffic.

## What this extension does

The extension keeps authenticated requests working in Burp by obtaining tokens through a real browser, then injecting the token into outgoing requests (header or cookie mode).

In practice:

- It can launch an automated login journey (redirects, forms, waits, clicks).
- It can refresh tokens on a schedule.
- It can detect session loss and recover automatically (if enabled).
- It keeps cache layers to avoid unnecessary re-logins, so that the external browser is not launched too many times 

## Why browser-based auth instead of regex token extraction

Traditional regex-based strategies often assume a simple, stable authentication response (for example: the user sends it's usernames/password and gets a cookie). That works for basic setups, but breaks more easily in modern enterprise auth.

Browser-based orchestration is usually more robust for complex flows:

- Handles multi-step redirects (SSO, IdP, external login pages).
- Works with JavaScript-heavy login pages where token retrieval is not a single direct API response.
- More resilient when authentication internals change but user-facing login still works.

This is especially useful in complex environments where authentication is distributed across several domains, identity providers, and intermediate pages.

## Workflow

0. If not done yet, install and start the API from the "API" tab.
1. Browser orchestration: enter the login URL and record the steps.
2. Token configuration: indicate where the token appears when authenticating.
3. Session lost detection: choose how and wether logout is detected.
4. Scope: self explanatory I guess.

## Caches overview

There are two cache systems:

- Local cache (inside Burp): keeps a recently fetched token so Burp does not call the API for every request.
- API cache (inside the token service): keeps tokens on the API side and can refresh them over time. The API launches the browser authentication journey if the token is expired, or if the session has been detected as lost.

### How they work together

- Burp checks its local cache first.
- If local cache is empty or expired, Burp asks the API for a token.
- The API returns a cached token when possible, or runs the browser flow to fetch a new one.

### When to clear which cache

- Use `Empty local token cache` when Burp keeps using an old token.
- Use `Empty API cache` when the token service should forget all stored tokens.

## Creating self-refreshing tokens tags

Hackvertor is another Burp extension that allows creating custom tags, and it has strong synergy with Browser Powered Session Handler.

You can create Hackvertor tags that act as auto-refreshing tokens for each user you want to test data segregation with.

for example, if you have user 1, user 2, and user admin, you can create the following Hackvertor tags:

<@_jwt_user_1/>, <@_jwt_user_2/> <@_jwt_admin/>

Each custom tag will be replaced with the right user-specific token automatically in your requests.

### How to create a tag

1. Install Hackvertor.
2. Configure your authentication in Browser Powered Session Handler.
3. Click `Copy hackvertor tag`.
4. In Burp top menu, click `Hackvertor`.
5. Click `Create custom tag`.
6. Set Tag name
7. Select language `Python`.
8. Paste the copied code in the code box.
9. Press "Create tag"

The tag can now be used anywhere as an auto-refreshing token, with tag <@_\<TAGNAME\>/>.

An execution key is also necessary for those tags. See Hackvertor wiki for more informations.

### Using those tags

With a normal setup, you need to authenticate as each user, and when tokens expire, do it again.

If you use these tags instead, Browser Powered Session Handler will automatically authenticate each user for you through the API-backed tag replacement flow.

Those tags can be used, for example, with Authmatrix, and instead of manually providing the tokens, you provide those tags, and never have to worry about re-authenticating with each of your users every X minutes.

For segregation testing with many users/roles, the time gained is enormous.

## API endpoints

- `GET /health` - health check
- `POST /config` - update token configuration
- `POST /token` - fetch token using the current auth flow
- `GET /cache` - show tokens currently stored in API cache
- `GET /invalidate` - clear API cache

## PKCS#11 authentication (beta)

The PKCS#11 flow is currently **very untested** and should be treated as experimental.

Current setup expectations:

1. The embedded Firefox used by Playwright is installed under `.\api\browsers`.
2. You must configure Firefox manually with the correct PKCS#11 module (your vendor DLL).
3. For now, the easiest way is:
   - Start an authentication flow with at least one waiting step (for example `wait_time`) so the browser stays open.
   - While the browser is open, configure PKCS#11 manually in Firefox.
   - Then continue/retry the authentication flow.

Reference for PKCS#11 setup:
- https://developer.mozilla.org/fr/docs/Mozilla/Add-ons/WebExtensions/API/pkcs11
