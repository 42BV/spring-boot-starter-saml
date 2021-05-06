package nl._42.boot.saml;

import nl._42.boot.saml.user.SAMLUserService;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class ConfigurationTest extends AbstractApplicationTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    public void userDetailService_shouldSucceed() {
        SAMLUserService service = applicationContext.getBean(SAMLUserService.class);
        assertNotNull(service);
    }

    @Test
    public void properties_shouldSucceed() {
        SAMLProperties properties = applicationContext.getBean(SAMLProperties.class);
        assertNotNull(properties);

        // Verify properties (test/resources/application.yaml)
        assertEquals(true, properties.isForceAuthN());
    }

}
