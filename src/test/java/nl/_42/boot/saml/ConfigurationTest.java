package nl._42.boot.saml;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ConfigurationTest {

    @Autowired
    private SAMLUserDetailsService samlUserDetailsService;

    @Test
    public void loads() {
        assertNotNull(samlUserDetailsService);
    }

}
