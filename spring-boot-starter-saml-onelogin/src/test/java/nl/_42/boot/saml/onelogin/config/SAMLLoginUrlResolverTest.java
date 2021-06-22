package nl._42.boot.saml.onelogin.config;

import nl._42.boot.saml.onelogin.AbstractApplicationTest;
import nl._42.boot.saml.onelogin.SAMLProperties;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.assertEquals;

public class SAMLLoginUrlResolverTest extends AbstractApplicationTest {

    @Autowired
    private SAMLLoginUrlResolver resolver;

    @Test
    public void resolveWith_whenDisabled_shouldSucceedEmpty() {
        SAMLProperties properties = new SAMLProperties();

        MockHttpServletRequest request = new MockHttpServletRequest();
        String loginUrl = new SAMLLoginUrlResolver(properties).getLoginUrl(request);
        assertEquals("", loginUrl);
    }

    @Test
    public void resolveWith_shouldSucceed() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String loginUrl = resolver.getLoginUrl(request);
        assertEquals("https://unit-test/saml/login", loginUrl);
    }

    @Test
    public void resolveWith_withSuccessUrlParameter_shouldSucceed() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("successUrl", "42.nl/congrats");

        String loginUrl = resolver.getLoginUrl(request);
        assertEquals("https://unit-test/saml/login?successUrl=42.nl/congrats", loginUrl);
    }

}
