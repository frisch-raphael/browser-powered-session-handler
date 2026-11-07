package lab.federation;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

/** Protected identity from the maintained resource filter; no token/code/refresh value is returned. */
@RestController
@ConditionalOnProperty(name="lab.federation.role", havingValue="resource")
public class FederationEndpoints {
    @GetMapping("/api/me")
    public Map<String,Object> identity(@AuthenticationPrincipal Jwt token) {
        var result = new LinkedHashMap<String,Object>();
        result.put("subject", token.getSubject()); result.put("issuer", token.getIssuer().toString());
        result.put("audience", token.getAudience()); result.put("providerSessionId", token.getClaimAsString("sid"));
        result.put("tokenId", token.getId());
        return result;
    }
}
