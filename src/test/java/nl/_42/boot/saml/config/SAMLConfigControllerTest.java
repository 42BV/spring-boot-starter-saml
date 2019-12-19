package nl._42.boot.saml.config;

import nl._42.boot.saml.AbstractWebTest;
import nl._42.boot.saml.SAMLProperties;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class SAMLConfigControllerTest extends AbstractWebTest {

    @Before
    public void setUp() {
        SAMLProperties properties = new SAMLProperties();
        properties.setEnabled(true);
        properties.setSpBaseUrl("https://test/authentication/idp/sso");

        SAMLLoginUrlResolver resolver = new SAMLLoginUrlResolver(properties);
        initWebClient(new SAMLConfigController(resolver));
    }

    @Test
    public void getConfig_shouldSucceed() throws Exception {
        webClient.perform(get("/saml/config"))
                 .andExpect(status().isOk())
                 .andExpect(jsonPath("loginUrl").value(startsWith("https://test/authentication/idp/sso")));
    }

    @Test
    public void getConfig_shouldSucceed_withSuccessUrl() throws Exception {
        webClient.perform(get("/saml/config?successUrl=http://www.42.nl/success"))
                 .andExpect(status().isOk())
                 .andExpect(jsonPath("loginUrl").value(startsWith("https://test/authentication/idp/sso")))
                 .andExpect(jsonPath("loginUrl").value(containsString("http://www.42.nl/success")));
    }

}
