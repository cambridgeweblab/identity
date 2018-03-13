package ucles.weblab.common.identity.auth0;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import ucles.weblab.common.identity.ExtendedUser;

/**
 * A strategy for resolving attributes based on what authentication mechanism we are using.
 *
 * @see org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter for other ideas
 */
@RequiredArgsConstructor
@Slf4j
public class UserAttributesResolver {

    private static final String NICKNAME_CLAIM = "http://ucles.org.uk/nickname";

    private final Authentication authentication;

    public String getUsername() {
        return authentication.getName();
    }

    public String getUserId() {
        if (authentication instanceof OAuth2Authentication) {
            OAuth2Authentication auth2Authentication = (OAuth2Authentication) authentication;
            Object principal = auth2Authentication.getUserAuthentication().getPrincipal();

            if (principal instanceof ExtendedUser) {
                return getUserIdFromExtendedUser((ExtendedUser) principal);
            } else {
                return principal.toString();
            }
        }

        if (authentication.getPrincipal() instanceof ExtendedUser) {
            return getUserIdFromExtendedUser((ExtendedUser) authentication.getPrincipal());
        }

        String uid = "user|" + authentication.getName();
        log.warn("Returning fabricated id: {} for getUserId for Authentication: {}", uid, authentication.getClass().toString());
        return uid;
    }

    private String getUserIdFromExtendedUser(ExtendedUser principal) {
        return (String) principal.getMetadata().get("sub");
    }

    public String getNickname() {
        Object principal = authentication.getPrincipal();
        if (principal instanceof ExtendedUser) {
            return (String) ((ExtendedUser) principal).getMetadata().get(NICKNAME_CLAIM);
        }
        return (String) principal;
    }

    public boolean hasAuthority(String role) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).anyMatch(role::equalsIgnoreCase);
    }
}