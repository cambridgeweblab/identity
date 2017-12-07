package ucles.weblab.common.identity.auth0;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth0")
@Data
public class Auth0Settings {
    private String domain;
    private String apiKey;
    private Mgmt mgmt = new Mgmt();

    @Data
    public static class Mgmt {

        private String clientId;

        private String clientSecret;

        private String connectionName;
    }
}
