package ucles.weblab.common.identity.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.users.User;
import com.auth0.net.Request;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;
import ucles.weblab.common.identity.ExtendedUser;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;


@RequiredArgsConstructor
public class UserDetailsManagerAuth0 implements UserDetailsManager {

    private static final String AUTH0_CONNECTION = "Username-Password-Authentication";
    private static final String AUTHORITIES = "authorities";

    private final String domain;

    private final String clientId;

    private final String clientSecret;


    private AuthAPI getAuthAPI() {
        return new AuthAPI(domain, clientId, clientSecret);
    }

    /**
     * Use authAPI to get an appropriate token for doing API stuff
     */
    private ManagementAPI getManagementAPI() {
        AuthAPI authAPI = getAuthAPI();

        String token;
        try {
            // See https://auth0.com/docs/api/management/v2/tokens for getting token for providing the API
            token = authAPI.requestToken(domain + "api/v2/").execute().getAccessToken();
        } catch (Auth0Exception e) {
            throw new AuthenticationServiceException("Unable to get access token due to Auth0 exception", e);
        }

        return new ManagementAPI(domain, token);
    }

    /** Create a user, returning the Auth0 user_id so that we have it for all other API calls */
    public String createUserForUserId(UserDetails user) {
        return createUserInternal(user).getId();
    }

    @Override
    public void createUser(UserDetails user) {
        createUserInternal(user);
    }

    private User createUserInternal(UserDetails user) {
        Assert.isTrue(user instanceof ExtendedUser, "User must be an instanceof ExtendedUser");
        ExtendedUser u = (ExtendedUser) user;
        Assert.isTrue(u.getUsername().equals("-ignored-") || !userExists(u.getUsername()), "User already exists");

        User dto = toAuth0User(u);
        Request<User> request = getManagementAPI().users().create(dto);
        try {
            return request.execute();
        } catch (Auth0Exception e) {
            throw new AuthenticationServiceException("Unable to add user due to Auth0 exception", e);
        }
    }

    @Override
    public void updateUser(UserDetails userDetails) {
        User user = toAuth0User((ExtendedUser) userDetails);
        try {
            getManagementAPI().users().update(userDetails.getUsername(), user).execute();
        } catch (Auth0Exception e) {
            throw new RuntimeException(e.getMessage(), e); // TODO: Review exception to use
        }
    }

    @Override
    public void deleteUser(String username) {
        try {
            getManagementAPI().users().delete(username).execute();
        } catch (Auth0Exception e) {
            throw new UsernameNotFoundException(username, e);
        }
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean userExists(String username) { // See https://auth0.com/docs/api/management/v2/user-search to search by email
        try {
            User user = getManagementAPI().users().get(username, null).execute();
            return user != null;
        } catch (Auth0Exception e) {
            if (e instanceof APIException && ((APIException) e).getStatusCode() == 404) {
                return false;
            }
            throw new AuthenticationServiceException("Unable to check for existing user due to Auth0 exception", e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            User user = getManagementAPI().users().get(username, null).execute();
            return new ExtendedUser(username,
                    user.getGivenName(),
                    user.getFamilyName(),
                    "-unknown-",
                    extractAuthorities(user.getAppMetadata()),
                    user.getEmail(),
                    user.getAppMetadata());
        } catch (Auth0Exception e) {
            throw new UsernameNotFoundException(username, e);
        }
    }

    private User toAuth0User(ExtendedUser u) {
        final String[] roles = u.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);
        final Map<String, Object> appMetadata = new HashMap<>();
        appMetadata.put(AUTHORITIES, roles);
        // copy all entries to app metadata
        u.getMetadata().forEach(appMetadata::put);

        User dto = new User(AUTH0_CONNECTION);
        dto.setName(u.getGivenName());
        dto.setGivenName(u.getGivenName());
        dto.setFamilyName(u.getFamilyName());
        dto.setPassword(u.getPassword());
        dto.setEmail(u.getEmail());
        dto.setAppMetadata(appMetadata);
        return dto;
    }

    private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> appMetadata) {
        @SuppressWarnings("unchecked")
        List<String> authorities = (List<String>) appMetadata.get(AUTHORITIES);
        return authorities == null
                ? emptyList()
                : authorities.stream().map(SimpleGrantedAuthority::new).collect(toList());
    }
}

