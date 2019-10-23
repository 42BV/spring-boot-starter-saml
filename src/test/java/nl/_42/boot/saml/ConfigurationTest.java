package nl._42.boot.saml;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import static org.junit.Assert.assertNotNull;

public class ConfigurationTest extends AbstractApplicationTest {

    @Autowired
    private SAMLUserDetailsService samlUserDetailsService;

    @Test
    public void loads() {
        assertNotNull(samlUserDetailsService);
    }

}
