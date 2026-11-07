import Keycloak from '/vendor/keycloak.js';

const status = document.querySelector('#login-status');
function fail(stage) {
  status.id = 'auth-error';
  status.dataset.stage = stage;
  status.textContent = `Sign-in could not complete during ${stage}.`;
}
try {
  const configResponse = await fetch('/spa-config', {cache: 'no-store'});
  if (!configResponse.ok) throw new Error('configuration');
  const config = await configResponse.json();
  const requested = new URL(location.href).searchParams.get('client');
  if (location.pathname === '/spa') {
    sessionStorage.setItem('authlab-client', ['cookie-verifier','upstream-cookie-verifier'].includes(requested) ? requested : 'browser-client');
    sessionStorage.setItem('authlab-broker', config.brokerEnabled && new URL(location.href).searchParams.get('broker') === 'upstream-saml' ? 'upstream-saml' : '');
  }
  const selectedClient = sessionStorage.getItem('authlab-client');
  const upstream = selectedClient === 'upstream-cookie-verifier';
  if (upstream && !config.upstreamUrl) throw new Error('configuration');
  const clientId = selectedClient === 'browser-client' ? 'browser-client' : 'cookie-verifier';
  const providerUrl = upstream ? config.upstreamUrl : config.url;
  const realm = upstream ? 'authlab-upstream' : config.realm;
  const adapter = new Keycloak({url: providerUrl, realm, clientId});
  if (sessionStorage.getItem('authlab-broker') === 'upstream-saml') {
    const login = adapter.login.bind(adapter);
    adapter.login = (options = {}) => login({...options, idpHint: 'upstream-saml'});
  }
  const authenticated = await adapter.init({
    onLoad: clientId === 'cookie-verifier' ? 'check-sso' : 'login-required',
    responseMode: 'query', pkceMethod: 'S256', redirectUri: `${config.clientOrigin}/spa/callback`,
    checkLoginIframe: false, enableLogging: false
  });
  if (!authenticated) {
    fail('sso-session-absent');
  } else if (upstream) {
    const identity = await fetch(`${providerUrl}/realms/${realm}/protocol/openid-connect/userinfo`, {headers: {Authorization: `Bearer ${adapter.token}`}, cache: 'no-store'});
    if (!identity.ok) throw new Error('sso-identity');
    const verified = await identity.json();
    if (typeof verified.sub !== 'string' || !verified.sub) throw new Error('sso-identity');
    status.dataset.subject = verified.sub;
    status.id = 'login-complete'; status.textContent = 'Selected SSO cookie authenticated the identity service.';
  } else {
    const headers = {Authorization: `Bearer ${adapter.token}`};
    const session = await fetch('/session', {method: 'POST', headers, credentials: 'same-origin', cache: 'no-store'});
    if (!session.ok) throw new Error('client-session');
    const client = await session.json();
    document.querySelector('#client-proof').textContent = 'Client session accepted.';
    const api = await fetch(`${config.resourceOrigin}/api/me`, {headers, cache: 'no-store'});
    if (!api.ok) throw new Error('protected-api');
    const resource = await api.json();
    if (resource.subject !== client.subject || resource.tokenId !== client.tokenId || resource.providerSessionId !== client.providerSessionId) throw new Error('protected-identity');
    document.querySelector('#api-proof').textContent = 'Protected API accepted the access token.';
    const pair = await fetch('/combined', {headers, credentials: 'same-origin', cache: 'no-store'});
    if (!pair.ok || (await pair.json()).issuanceId !== client.issuanceId) throw new Error('combined-credentials');
    document.querySelector('#combined-proof').textContent = 'Client cookie and the same access token accepted together.';
    status.id = 'login-complete'; status.textContent = 'Sign-in completed and protected access verified.';
  }
} catch (error) {
  const stage = ['configuration','client-session','protected-api','protected-identity','combined-credentials','sso-identity'].includes(error?.message) ? error.message : 'authorization';
  fail(stage);
}
