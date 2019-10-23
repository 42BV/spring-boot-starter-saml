package nl._42.boot.saml.http;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;

public class SAMLFailureHandlerTest {

    private SAMLFailureHandler handler;

    @Before
    public void setUp() {
        handler = new SAMLFailureHandler();
        handler.setForbiddenUrl("forbidden");
        handler.setExpiredUrl("expired");
    }

    @Test
    public void no_cookies() {
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new UsernameNotFoundException("Abc"));

        assertEquals(
          "expired",
          response.getHeader("Location")
        );
    }

}
