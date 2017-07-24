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

@Slf4j
@RequiredArgsConstructor
public class Auth0UserAuthenticationConverter extends DefaultUserAuthenticationConverter {

    private final String usernameAttributeKey;


    @Override
    public Authentication extractAuthentication(Map<String, ?> map) {

        if (!map.containsKey(usernameAttributeKey)) {
            log.warn("No username attribute: {} found in JWT. Returning null Authentication", usernameAttributeKey);
            return null;
        }

        String username = (String) map.get(usernameAttributeKey);
        Collection<? extends GrantedAuthority> authorities = getAuthorities(map);
        ExtendedUser user = new ExtendedUser(username,
                (String) map.get(GIVEN_NAME), (String) map.get(FAMILY_NAME),
                "n/a pwd",
                authorities, null, map);
        return new UsernamePasswordAuthenticationToken(user, "N/A", authorities);
    }

    private Collection<? extends GrantedAuthority> getAuthorities(Map<String, ?> map) {
        Object authorities = map.get(AUTHORITIES);
        if (authorities instanceof String) {
            return AuthorityUtils.commaSeparatedStringToAuthorityList((String) authorities);
        }
        if (authorities instanceof Collection) {
            return AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
                    .collectionToCommaDelimitedString((Collection<?>) authorities));
        }
        log.warn("No authorities found in JWT. Returning empty list");
        return emptyList();
    }
}
