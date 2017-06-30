package ucles.weblab.common.identity;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Map;

@Getter
public class ExtendedUser extends User {

    private final String email;

    private final Map<String, Object> metadata;

    /**
     *
     * @param metadata e.g. singletonMap("ielts", singletonMap("roId", 12))
     */
    public ExtendedUser(String username, String password, Collection<? extends GrantedAuthority> authorities,
                        String email, Map<String, Object> metadata) {
        super(username, password, authorities);
        this.email = email;
        this.metadata = metadata;
    }
}
