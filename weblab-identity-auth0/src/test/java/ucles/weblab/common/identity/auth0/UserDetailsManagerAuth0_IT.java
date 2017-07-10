package ucles.weblab.common.identity.auth0;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import ucles.weblab.common.identity.ExtendedUser;

import java.util.Map;
import java.util.UUID;

import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;

@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", value = "local") // We have to configure this and run locally to test against live Auth0 system
@SpringBootTest(webEnvironment = WebEnvironment.NONE)
@TestPropertySource(
        locations = {"classpath:application-test.properties", "classpath:application-test-local.properties"})
public class UserDetailsManagerAuth0_IT {

    @Autowired
    UserDetailsManagerAuth0 userDetailsManager;

    @Configuration
    @EnableAutoConfiguration
    public static class Config {

        @Value("${auth0.domain}")
        String domain;

        @Value("${auth0.mgmt.client-id}")
        String clientId;

        @Value("${auth0.mgmt.client-secret}")
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
    public void it_createsAndDeletesAUser() {
        String uuid = UUID.randomUUID().toString();
        String email = uuid + "@tapina.com";
        Map<String, Object> metadata = singletonMap("ielts", singletonMap("roId", 12));
        String id = userDetailsManager.createUserForUserId(
                new ExtendedUser("Tommy", "Tippee","letmein", createAuthorityList("ROLE_ADMIN"), email, metadata));
        assertThat(id).startsWith("auth0|");
        assertThat(id).hasSize(30);
        UserDetails user = userDetailsManager.loadUserByUsername(id);
        assertThat(user).isNotNull();
        userDetailsManager.deleteUser(id);
        try {
            userDetailsManager.loadUserByUsername(id);
            Assertions.fail("Should have thrown UserNameNotFoundException");
        } catch (UsernameNotFoundException e) {
            // success here
        }
    }
}

