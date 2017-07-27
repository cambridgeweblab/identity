package ucles.weblab.common.identity.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.tickets.PasswordChangeTicket;
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

import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;


@RequiredArgsConstructor
public class UserDetailsManagerAuth0 implements UserDetailsManager {

    private static final String AUTHORITIES = "authorities";
    static final String GIVEN_NAME = "givenName";
    static final String FAMILY_NAME = "familyName";

    private final String domain;

    /** Connection in Auth0 for where credentials are stored. e.g. Username-Password-Authentication */
    private final String connectionName;

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
        user.setPassword(null); // hack to get around non-null password in ExtendedUser.
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

    /**
     * Obtains a URI to a web page where the user can reset their password.
     * Once the user has reset their password, they will be redirected to the specified URI.
     *
     * @param userId the user ID (note, not email address) e.g. the return value from {@link #createUserForUserId(UserDetails)}.
     * @param redirectUri the URI to send the user to after they have reset their password
     * @return the URI to give to the user to reset their password e.g. in an e-mail or browser redirection.
     */
    public URI getChangePasswordUri(String userId, URI redirectUri) {
        final PasswordChangeTicket request = new PasswordChangeTicket(userId);
        request.setResultUrl(redirectUri.toString());
        try {
            final PasswordChangeTicket response = getManagementAPI().tickets().requestPasswordChange(request).execute();
            return URI.create(response.getTicket());
        } catch (Auth0Exception e) {
            throw new RuntimeException(e.getMessage(), e); // TODO: Review exception to use.
        }
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
                    (String) user.getUserMetadata().get(GIVEN_NAME),
                    (String) user.getUserMetadata().get(FAMILY_NAME),
                    "-unknown-",
                    extractAuthorities(user.getAppMetadata()),
                    user.getEmail(),
                    user.getAppMetadata());
        } catch (Auth0Exception e) {
            throw new UsernameNotFoundException(username, e);
        }
    }

    private User toAuth0User(ExtendedUser u) {
        User dto = new User(connectionName);
        dto.setPassword(u.getPassword());
        dto.setEmail(u.getEmail());
        dto.setVerifyEmail(false);

        // APP_METADATA
        String[] roles = u.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);

        Map<String, Object> appMetadata = new HashMap<>();
        appMetadata.put(AUTHORITIES, roles);
        u.getMetadata().forEach(appMetadata::put);
        dto.setAppMetadata(appMetadata);

        // USER_METADATA
        Map<String, Object> userMetadata = new HashMap<>();
        userMetadata.put(GIVEN_NAME, u.getGivenName());
        userMetadata.put(FAMILY_NAME, u.getFamilyName());
        dto.setUserMetadata(userMetadata);
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

