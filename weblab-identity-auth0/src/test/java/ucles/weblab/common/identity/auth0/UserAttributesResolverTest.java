package ucles.weblab.common.identity.auth0;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.spring.security.api.authentication.AuthenticationJsonWebToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import ucles.weblab.common.identity.ExtendedUser;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class UserAttributesResolverTest {

    private final String someUserId = "someuserid";
    private final String someName = "freda";

    @Test
    public void shouldReturnJWTWhenGetId() {
        Authentication authentication = mock(AuthenticationJsonWebToken.class);
        DecodedJWT decodedJWT = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);
        UserAttributesResolver userAttributesResolver = new UserAttributesResolver(authentication);

        when(authentication.getDetails()).thenReturn(decodedJWT);
        when(decodedJWT.getClaim(anyString())).thenReturn(claim);
        when(claim.asString()).thenReturn(someUserId);

        assertEquals(userAttributesResolver.getUserId(), someUserId);
        verify(decodedJWT, times(1)).getClaim("sub");
    }

    @Test
    public void shouldReturnOAuth2WhenGetId() {
        OAuth2Authentication oAuth2Authentication = mock(OAuth2Authentication.class);
        Authentication authentication = mock(Authentication.class);
        Object principal = mock(Object.class);
        UserAttributesResolver userAttributesResolver = new UserAttributesResolver(oAuth2Authentication);

        when(oAuth2Authentication.getUserAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(principal);
        when(principal.toString()).thenReturn(someUserId);

        assertEquals(userAttributesResolver.getUserId(), someUserId);
        verify(authentication, never()).getName();
    }

    @Test
    public void shouldReturnOAuth2ExtendedUserWhenGetId() {
        OAuth2Authentication oAuth2Authentication = mock(OAuth2Authentication.class);
        Authentication authentication = mock(Authentication.class);

        ExtendedUser extendedUser = mock(ExtendedUser.class);
        UserAttributesResolver userAttributesResolver = new UserAttributesResolver(oAuth2Authentication);
        Map<String, Object> map = mock(HashMap.class);

        when(oAuth2Authentication.getUserAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(extendedUser);
        doReturn(map).when(extendedUser).getMetadata();
        when(map.get("sub")).thenReturn(someUserId);

        assertEquals(userAttributesResolver.getUserId(), someUserId);
        verify(map, times(1)).get("sub");
        verify(authentication, never()).getName();
    }

    @Test
    public void shouldReturnExtendedUserWhenGetId() {
        Authentication authentication = mock(Authentication.class);
        ExtendedUser extendedUser = mock(ExtendedUser.class);
        UserAttributesResolver userAttributesResolver = new UserAttributesResolver(authentication);
        Map<String, Object> map = mock(HashMap.class);

        when(authentication.getPrincipal()).thenReturn(extendedUser);
        doReturn(map).when(extendedUser).getMetadata();
        when(map.get("sub")).thenReturn(someUserId);

        assertEquals(userAttributesResolver.getUserId(), someUserId);
        verify(map, times(1)).get("sub");
    }

    @Test
    public void shouldReturnFredaWhenGetId() {
        Authentication authentication = mock(Authentication.class);
        UserAttributesResolver userAttributesResolver = new UserAttributesResolver(authentication);

        when(authentication.getName()).thenReturn(someName);

        assertEquals(userAttributesResolver.getUserId(), "user|" + someName);
    }

}