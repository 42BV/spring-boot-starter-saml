package nl._42.boot.saml;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ConfigurationTest extends AbstractApplicationTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    public void userDetailService_shouldSucceed() {
        SAMLUserDetailsService service = applicationContext.getBean(SAMLUserDetailsService.class);
        assertNotNull(service);
    }

    @Test
    public void properties_shouldSucceed() {
        SAMLProperties properties = applicationContext.getBean(SAMLProperties.class);
        assertNotNull(properties);

        // Verify properties (test/resources/application.yaml)
        assertEquals(600, properties.getResponseSkew());
    }

}
