package ucles.weblab.common.identity.auth0;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;

@Slf4j
public class Auth0AccessTokenConverter extends DefaultAccessTokenConverter {

    public Auth0AccessTokenConverter(String namespace, String usernameAttributeKey) {
        super();

        setUserTokenConverter(new Auth0UserAuthenticationConverter(namespace, usernameAttributeKey));
    }
}
