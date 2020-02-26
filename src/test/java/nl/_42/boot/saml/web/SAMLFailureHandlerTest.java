package nl._42.boot.saml.web;

import nl._42.boot.saml.AbstractApplicationTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.Assert.assertEquals;

public class SAMLFailureHandlerTest extends AbstractApplicationTest {

    @Autowired
    private SAMLFailureHandler handler;

    @Test
    public void no_cookies() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteHost("https://localhost");

        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new UsernameNotFoundException("Abc"));

        assertEquals(
          "https://localhost/expired",
          response.getHeader("Location")
        );
    }

}
