package ucles.weblab.common.identity;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Map;

@Getter
public class ExtendedUser extends User {

    private final String email;

    private final String givenName;

    private final String familyName;

    private final Map<String, ?> metadata;


    /**
     * Create a user.<br>
     * @param username
     *  This is opinionated towards systems that do not allow/require a username, but return a unique user_id.
     *  As the superclass requires a username, it will be set to <code>"-ignored-"</code> if not provided.
     * @param metadata e.g. singletonMap("ielts", singletonMap("roId", 12))
     */
    public ExtendedUser(
            String username,
            String givenName, String familyName,
            String password, Collection<? extends GrantedAuthority> authorities,
            String email, Map<String, ?> metadata) {
        super(username == null ? "-ignored-" : username, password, authorities);
        this.email = email;
        this.metadata = metadata;
        this.givenName = givenName;
        this.familyName = familyName;
    }
}
