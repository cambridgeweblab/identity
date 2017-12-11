package ucles.weblab.common.identity.auth0;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.util.StringUtils;
import ucles.weblab.common.identity.ExtendedUser;

import java.util.Collection;
import java.util.Map;

import static java.util.Collections.emptyList;
import static ucles.weblab.common.identity.auth0.UserDetailsManagerAuth0.FAMILY_NAME;
import static ucles.weblab.common.identity.auth0.UserDetailsManagerAuth0.GIVEN_NAME;

/**
 * Responsible for extracting things Spring Security needs.
 *
 * For OIDC Conformant JWTs we have to specify a namespace prefix
 */
@Slf4j
@RequiredArgsConstructor
public class Auth0UserAuthenticationConverter extends DefaultUserAuthenticationConverter {

    /** Prefix for property within the JWT.  e.g. http://ucles.org.uk/ */
    private final String namespacePrefix;

    private final String usernameAttributeKey;


    @Override
    public Authentication extractAuthentication(Map<String, ?> map) {

        String usernamePath = withNamespace(usernameAttributeKey);
        if (!map.containsKey(usernamePath)) {
            log.warn("No username attribute: {} found in JWT. Returning null Authentication", usernameAttributeKey);
            return null;
        }

        String username = (String) map.get(usernamePath);
        Collection<? extends GrantedAuthority> authorities = getAuthorities(username, map);
        ExtendedUser user = new ExtendedUser(username,
                (String) map.get(withNamespace(GIVEN_NAME)), (String) map.get(withNamespace(FAMILY_NAME)),
                "n/a pwd",
                authorities, null, map);
        return new UsernamePasswordAuthenticationToken(user, "N/A", authorities);
    }

    private String withNamespace(String key) {
        return namespacePrefix == null ? key : namespacePrefix + key;
    }

    private Collection<? extends GrantedAuthority> getAuthorities(String username, Map<String, ?> map) {
        Object authorities = map.get(withNamespace(AUTHORITIES));
        if (authorities instanceof String) {
            return AuthorityUtils.commaSeparatedStringToAuthorityList((String) authorities);
        }
        if (authorities instanceof Collection) {
            return AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
                    .collectionToCommaDelimitedString((Collection<?>) authorities));
        }
        log.warn("No authorities found in JWT for {}. Returning empty list", username);
        return emptyList();
    }
}
