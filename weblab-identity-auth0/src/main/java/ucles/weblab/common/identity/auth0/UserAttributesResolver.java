package ucles.weblab.common.identity.auth0;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.spring.security.api.authentication.JwtAuthentication;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import ucles.weblab.common.identity.ExtendedUser;

/**
 * A strategy for resolving attributes based on what authentication mechanism we are using.
 * @see org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter for other ideas
 */
@RequiredArgsConstructor
public class UserAttributesResolver {

    private final Authentication authentication;

    public String getUsername() {
        return authentication.getName();
    }

    public String getNickname() {
        if (authentication instanceof JwtAuthentication) {
            DecodedJWT details = (DecodedJWT) authentication.getDetails();
            return details.getClaim("nickname").asString();
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof ExtendedUser) {
            return (String) ((ExtendedUser) principal).getMetadata().get("nickname");
        }
        return (String) principal;
    }

    public boolean hasAuthority(String role) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).anyMatch(role::equalsIgnoreCase);
    }
}