package ucles.weblab.common.identity.auth0;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Required to work around defaults in Spring so that we can call own readAuthentication.
 * @see https://github.com/spring-projects/spring-boot/issues/9551
 */
public class ConfigurableJwkTokenServices extends DefaultTokenServices {

    private final TokenStore tokenStore;
    private final DefaultAccessTokenConverter tokenConverter;

    public ConfigurableJwkTokenServices(TokenStore tokenStore, String namespace, String usernameAttributeKey) {
        super.setTokenStore(tokenStore);
        this.tokenStore = tokenStore; // need to keep a reference

        tokenConverter = new Auth0AccessTokenConverter(namespace, usernameAttributeKey);
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException, InvalidTokenException {

        OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenValue);
        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        }
        else if (accessToken.isExpired()) {
            tokenStore.removeAccessToken(accessToken);
            throw new InvalidTokenException("Access token expired: " + accessTokenValue);
        }

//        OAuth2Authentication result = tokenStore.readAuthentication(accessToken);
        OAuth2Authentication result = readAuthentication(accessToken);
        if (result == null) {
            // in case of race condition
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        }
        return result;
    }

    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return tokenConverter.extractAuthentication(token.getAdditionalInformation());
    }

}
