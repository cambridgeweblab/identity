package ucles.weblab.common.identity.auth0;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.spring.security.api.authentication.AuthenticationJsonWebToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * A strategy for resolving attributes based on what authentication mechanism we are using.
 * @see org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter for other ideas
 */
@RequiredArgsConstructor
public class UserAttributesResolver {

    private final Authentication authentication;

    String getUsername() {
        return authentication.getName();
    }

    String getNickname() {
        if (authentication instanceof AuthenticationJsonWebToken) {
            DecodedJWT details = (DecodedJWT) authentication.getDetails();
            return details.getClaim("nickname").asString();
        }
        return (String) authentication.getPrincipal();
    }

    boolean hasAuthority(String role) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).anyMatch(role::equalsIgnoreCase);
    }
}