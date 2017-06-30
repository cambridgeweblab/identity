package ucles.weblab.common.identity.auth0;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import ucles.weblab.common.identity.ExtendedUser;

import java.util.UUID;

import static org.junit.Assert.assertNotNull;
import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;

@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", value = "local") // We have to configure this and run locally to test against live Auth0 system
@SpringBootTest(webEnvironment = WebEnvironment.NONE)
@TestPropertySource(
        locations = {"classpath:application-test.properties", "classpath:application-test-local.properties"})
public class UserDetailsManagerAuth0_IT {

    @Autowired
    UserDetailsManager userDetailsManager;

    @Configuration
    @EnableAutoConfiguration
    public static class Config {

        @Value("${auth0.domain}")
        String domain;

        @Value("${auth0.mgmt.clientId}")
        String clientId;

        @Value("${auth0.mgmt.clientSecret}")
        String clientSecret;


        @Bean
        UserDetailsManager userDetailsManager() {
            return new UserDetailsManagerAuth0(domain, clientId, clientSecret);
        }
    }

    @Test
    public void it_initialisesOk() {
        assertNotNull(userDetailsManager);
    }

    @Test
    public void it_createsAUser() {
        String uuid = UUID.randomUUID().toString().replaceAll("-", "");
        String username = "auth0|" + uuid;
        String email = uuid + "@tapina.com";
        userDetailsManager.createUser(new ExtendedUser(username, "letmein", createAuthorityList("ROLE_ADMIN"), email));
    }
}

