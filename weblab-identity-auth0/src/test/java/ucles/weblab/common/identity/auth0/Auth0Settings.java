package ucles.weblab.common.identity.auth0;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "weblab.ident.auth0.client")
@Data
public class Auth0Settings {
    private String domain;
    private String apiKey;
}
