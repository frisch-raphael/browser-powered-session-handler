package lab.federation;

import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;

/** Client cookie proof and exact bearer association; hidden backend tokens are never returned to the browser. */
@RestController
@ConditionalOnProperty(name="lab.federation.role",havingValue="client")
public final class FederationClientEndpoints implements AutoCloseable {
    private record Session(String subject,String providerSession,String tokenHash,String tokenId,String issuance,boolean apiAccepted,String protocol,long touched) {}
    private static final class Capacity extends RuntimeException {}
    private final Map<String,Session> sessions=new ConcurrentHashMap<>();
    private final FederationApplication.Settings settings;
    private final JwtDecoder decoder;
    private final HttpClient api;
    private final FederationProtocol protocol;
    private static final SecureRandom RANDOM=new SecureRandom();

    FederationClientEndpoints(FederationApplication.Settings settings,JwtDecoder decoder,SSLContext federationTrust,FederationProtocol protocol) {
        this.settings=settings;this.decoder=decoder;this.protocol=protocol;
        api=labHttpClient(federationTrust);
    }
    private static HttpClient labHttpClient(SSLContext trust) {
        return HttpClient.newBuilder().sslContext(trust).connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER)
                .proxy(new java.net.ProxySelector(){
                    @Override public List<java.net.Proxy> select(URI uri){return List.of(java.net.Proxy.NO_PROXY);}
                    @Override public void connectFailed(URI uri,java.net.SocketAddress address,IOException error){}
                }).build();
    }

    /** Serves only nonsecret adapter configuration for the two fixed public fixture clients. */
    @GetMapping("/spa-config") public Map<String,Object> configuration() {
        String issuer=settings.issuer().toString();return Map.of("url",issuer.substring(0,issuer.indexOf("/realms/")),"realm","authlab-downstream",
                "clientOrigin",settings.clientOrigin().toString(),"resourceOrigin",settings.resourceOrigin().toString(),"brokerEnabled",settings.caseId().startsWith("FED.broker."),
                "upstreamUrl",settings.upstreamIssuer()==null?"":settings.upstreamIssuer().toString().replace("/realms/authlab-upstream",""));
    }
    @GetMapping(value={"/spa","/spa/callback"},produces="text/html") public String spa() throws IOException {
        try(var input=getClass().getResourceAsStream("/static/spa.html")){if(input==null)throw new IOException("Prepared SPA page absent.");return new String(input.readAllBytes(),StandardCharsets.UTF_8);}
    }

    /** Requires an actual validated access token, even if another Spring login session already exists. */
    @PostMapping("/session") public void establish(@AuthenticationPrincipal Jwt token,HttpServletResponse response) throws IOException {
        if(token==null){failure(response,401,"access_token_rejected");return;}
        protocol.checkpoint("before-client-session");
        try {String cookie=store(token,false);setCookie(response,cookie);protocol.clientCookieEstablished();json(response,200,identity(sessions.get(cookie)));}
        catch(Capacity full){failure(response,503,"client_session_capacity");}
    }
    @GetMapping("/me") public void me(HttpServletRequest request,HttpServletResponse response) throws IOException {
        var session=selected(request,response);if(session!=null)json(response,200,identity(session));
    }
    /** Invalidates only the client session; provider SSO remains available for the selected-cookie proof. */
    @PostMapping("/logout-client") public void logoutClient(HttpServletRequest request,HttpServletResponse response) throws IOException {
        if(selected(request,response)==null)return;
        for(var cookie:request.getCookies())if(cookie.getName().equals("LAB_CLIENT"))sessions.remove(cookie.getValue());
        response.addHeader("Set-Cookie",ResponseCookie.from("LAB_CLIENT","").httpOnly(true).secure(true).sameSite("None").path("/").maxAge(Duration.ZERO).build().toString());response.setStatus(204);
    }
    @GetMapping("/combined") public void combined(HttpServletRequest request,HttpServletResponse response,@AuthenticationPrincipal Jwt token) throws IOException {
        var session=selected(request,response);if(session==null)return;
        if(token==null||!session.protocol().equals("oidc")||!session.subject().equals(token.getSubject())||!Objects.equals(session.providerSession(),token.getClaimAsString("sid"))
                ||!MessageDigest.isEqual(session.tokenHash().getBytes(StandardCharsets.US_ASCII),hash(token.getTokenValue()).getBytes(StandardCharsets.US_ASCII))) {
            failure(response,401,"credential_pair_rejected");return;
        }
        json(response,200,identity(session));
    }

    /** The real backend exchange must produce a token actually accepted by the separate API before cookie publication. */
    void backendCompleted(HttpServletRequest request,HttpServletResponse response,Authentication authentication,OAuth2AuthorizedClientRepository clients) throws IOException {
        if(!(authentication instanceof OAuth2AuthenticationToken login)){failure(response,500,"client_login_state_absent");return;}
        OAuth2AuthorizedClient client=clients.loadAuthorizedClient(login.getAuthorizedClientRegistrationId(),authentication,request);
        if(client==null||client.getAccessToken()==null){failure(response,500,"client_access_token_absent");return;}
        String value=client.getAccessToken().getTokenValue();Jwt token;
        try {token=decoder.decode(value);}catch(JwtException invalid){failure(response,401,"access_token_rejected");return;}
        HttpResponse<byte[]> accepted;
        try {
            accepted=api.send(HttpRequest.newBuilder(URI.create(settings.resourceOrigin()+"/api/me")).timeout(Duration.ofSeconds(5)).header("Authorization","Bearer "+value).GET().build(),HttpResponse.BodyHandlers.ofByteArray());
        } catch(InterruptedException error){Thread.currentThread().interrupt();failure(response,503,"protected_api_interrupted");return;}
        catch(IOException error){failure(response,503,"protected_api_unavailable");return;}
        if(accepted.statusCode()!=200){failure(response,401,"protected_api_rejected");return;}
        try {
            var proof=FederationApplication.JSON.readTree(accepted.body());
            if(!token.getSubject().equals(proof.path("subject").asString())||!Objects.equals(token.getId(),proof.path("tokenId").asString(null))
                    ||!Objects.equals(token.getClaimAsString("sid"),proof.path("providerSessionId").asString(null))){failure(response,401,"protected_api_identity_mismatch");return;}
        } catch(RuntimeException invalid){failure(response,502,"protected_api_invalid_response");return;}
        String cookie;
        try {cookie=store(token,true);}catch(Capacity full){failure(response,503,"client_session_capacity");return;}
        setCookie(response,cookie);protocol.sessionEstablished();response.sendRedirect(settings.clientOrigin()+"/backend-complete");
    }
    @GetMapping("/backend-complete") public void backendComplete(HttpServletRequest request,HttpServletResponse response) throws IOException {
        var session=selected(request,response);if(session==null)return;
        if(!session.apiAccepted()){failure(response,409,"protected_api_not_verified");return;}
        response.setContentType("text/html; charset=utf-8");response.getWriter().write("<!doctype html><html><body><p id=login-complete>Backend login completed; protected API accepted its access token.</p></body></html>");
    }
    /** Safe failure text does not reuse raw provider descriptions, codes, verifiers or URLs. */
    void loginFailed(HttpServletResponse response,Exception error) throws IOException {
        String code=error instanceof OAuth2AuthenticationException known?known.getError().getErrorCode():"unknown";
        protocol.rejected(code);
        String stage=Set.of("invalid_token_response","invalid_grant").contains(code)?"token-exchange":"oauth-callback";
        boolean expired=protocol.simulatedResponseObserved()&&error instanceof OAuth2AuthenticationException known
                &&code.equals("invalid_grant")&&Objects.toString(known.getError().getDescription(),"").contains("Authorization code expired (simulated test condition)");
        String detail=expired?"Authorization code expired (simulated test condition).":"Login failed during "+stage+".";
        response.setStatus(400);response.setContentType("text/html; charset=utf-8");response.getWriter().write("<!doctype html><html><body><p id=auth-error data-stage=\""+stage+"\">"+detail+"</p></body></html>");
    }

    /** The one simulated expiry control still goes through the maintained client's actual HTTP/error parser. */
    @PostMapping("/cases/{caseId}/oauth/token-error") public void expiredCode(@PathVariable("caseId") String caseId,HttpServletRequest request,HttpServletResponse response) throws IOException {
        if(!settings.caseId().equals(caseId)||!protocol.simulatedExpiry()){failure(response,404,"not_found");return;}
        String type=request.getContentType();if(type==null||!type.split(";",2)[0].trim().equalsIgnoreCase("application/x-www-form-urlencoded")){failure(response,415,"form_body_required");return;}
        if(request.getInputStream().readNBytes(65_537).length>65_536){failure(response,413,"form_body_too_large");return;}
        protocol.expiredResponse();json(response,400,Map.of("error","invalid_grant","error_description","Authorization code expired (simulated test condition)"));
    }

    /** Only the maintained SAML success handler can publish this cookie; its assertion is never exported. */
    void samlCompleted(HttpServletResponse response,Authentication authentication) throws IOException {
        if(!(authentication instanceof org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication saml)
                ||!"keycloak".equals(saml.getRelyingPartyRegistrationId())||saml.getCredentials().getNameId()==null||saml.getCredentials().getNameId().isBlank()) {
            failure(response,400,"saml_session_identity_absent");return;
        }
        if(saml.getCredentials().getSessionIndexes().size()!=1||saml.getCredentials().getSessionIndexes().getFirst().isBlank()) {
            failure(response,400,"saml_provider_session_absent");return;
        }
        try {
            String cookie=store(saml.getCredentials().getNameId(),saml.getCredentials().getSessionIndexes().getFirst(),null,null,false,"saml");
            setCookie(response,cookie);response.sendRedirect(settings.clientOrigin()+"/saml-complete");
        }catch(Capacity full){failure(response,503,"client_session_capacity");}
    }
    @GetMapping("/saml-complete") public void samlComplete(HttpServletRequest request,HttpServletResponse response) throws IOException {
        var session=selected(request,response);if(session==null)return;
        if(!session.protocol().equals("saml")){failure(response,409,"saml_session_required");return;}
        response.setContentType("text/html; charset=utf-8");response.getWriter().write("<!doctype html><html><body><p id=login-complete>SAML login completed; the client accepted the signed identity.</p></body></html>");
    }
    void samlFailed(HttpServletResponse response,Exception error) throws IOException {
        String code="unclassified";
        if(error instanceof org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException known) {
            String value=known.getSaml2Error().getErrorCode();
            if(Set.of("unknown_response_class","malformed_request_data","malformed_response_data","invalid_request","invalid_response","invalid_destination","invalid_assertion",
                    "invalid_signature","subject_not_found","username_not_found","decryption_error","invalid_issuer","internal_validation_error","relying_party_registration_not_found","invalid_in_response_to").contains(value))code=value;
            String description=Objects.toString(known.getSaml2Error().getDescription(),"").toLowerCase(Locale.ROOT);
            var terms=List.of("signature","destination","issuer","audience","recipient","inresponseto","notonorafter","expired","subject").stream().filter(description::contains).toList();
            System.err.println("SAML response rejected; code="+code+"; validation terms="+String.join(",",terms));
        } else System.err.println("SAML response rejected; exception type="+error.getClass().getName());
        response.setStatus(400);response.setContentType("text/html; charset=utf-8");
        response.getWriter().write("<!doctype html><html><body><p id=auth-error data-stage=saml-response>Login failed during SAML response validation.</p></body></html>");
    }

    /** Keeps the exact validated token bytes associated with this new opaque client cookie. */
    private String store(Jwt token,boolean apiAccepted) {
        return store(token.getSubject(),token.getClaimAsString("sid"),hash(token.getTokenValue()),token.getId(),apiAccepted,"oidc");
    }
    private String store(String subject,String providerSession,String tokenHash,String tokenId,boolean apiAccepted,String protocol) {
        long now=System.nanoTime();sessions.entrySet().removeIf(e->now-e.getValue().touched()>TimeUnit.SECONDS.toNanos(90));
        if(sessions.size()>=4096)throw new Capacity();
        byte[] bytes=new byte[32];RANDOM.nextBytes(bytes);String cookie=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        sessions.put(cookie,new Session(subject,providerSession,tokenHash,tokenId,UUID.randomUUID().toString(),apiAccepted,protocol,now));return cookie;
    }
    private Session selected(HttpServletRequest request,HttpServletResponse response) throws IOException {
        var cookies=request.getCookies();String value=null;int count=0;
        if(cookies!=null)for(var cookie:cookies)if(cookie.getName().equals("LAB_CLIENT")){value=cookie.getValue();count++;}
        if(count>1){failure(response,400,"duplicate_client_cookie");return null;}
        var session=value==null?null:sessions.get(value);long now=System.nanoTime();
        if(session==null||now-session.touched()>TimeUnit.SECONDS.toNanos(90)){if(value!=null)sessions.remove(value);failure(response,401,"client_cookie_rejected");return null;}
        var touched=new Session(session.subject(),session.providerSession(),session.tokenHash(),session.tokenId(),session.issuance(),session.apiAccepted(),session.protocol(),now);sessions.put(value,touched);setCookie(response,value);return touched;
    }
    private static Map<String,Object> identity(Session session) {
        var value=new LinkedHashMap<String,Object>();value.put("subject",session.subject());value.put("providerSessionId",session.providerSession());value.put("tokenId",session.tokenId());value.put("issuanceId",session.issuance());value.put("authenticationProtocol",session.protocol());return value;
    }
    private static String hash(String value) {
        try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
        catch(NoSuchAlgorithmException error){throw new IllegalStateException("Required token association hash unavailable.");}
    }
    private static void setCookie(HttpServletResponse response,String value) {response.addHeader("Set-Cookie",ResponseCookie.from("LAB_CLIENT",value).httpOnly(true).secure(true).sameSite("None").path("/").maxAge(Duration.ofSeconds(90)).build().toString());}
    private static void json(HttpServletResponse response,int status,Object value) throws IOException {response.setStatus(status);response.setContentType("application/json");response.getOutputStream().write(FederationApplication.JSON.writeValueAsBytes(value));}
    void failure(HttpServletResponse response,int status,String code) throws IOException {json(response,status,Map.of("error",code));}
    @Override public void close(){sessions.clear();api.close();}
}
