package nl._42.boot.saml.springsecurity.web;

import nl._42.boot.saml.springsecurity.AbstractApplicationTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;

public class SAMLFailureHandlerTest extends AbstractApplicationTest {

    @Autowired
    private SAMLFailureHandler handler;

    @Test
    public void no_cookies() {
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new UsernameNotFoundException("Abc"));

        assertEquals(
          "/expired",
          response.getHeader("Location")
        );
    }

}
