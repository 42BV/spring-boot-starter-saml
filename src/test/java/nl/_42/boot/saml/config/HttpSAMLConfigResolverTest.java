package nl._42.boot.saml.config;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

public class HttpSAMLConfigResolverTest {

    private HttpSAMLConfigResolver resolver;

    private RestTemplate template;
    private MockHttpServletRequest request;

    @Before
    public void setUp() {
        request = new MockHttpServletRequest();
        template = Mockito.mock(RestTemplate.class);

        resolver = new HttpSAMLConfigResolver("https://test-provider/sso");
        resolver.setTemplate(template);
    }

    @Test
    public void resolveWith_shouldSucceed() {
        String location = "http://unit-test/api/saml/login";

        ResponseEntity<String> response = ResponseEntity.ok()
                .location(URI.create(location))
                .build();

        when(template.getForEntity("https://test-provider/sso/saml/login", String.class)).thenReturn(response);

        SAMLConfig config = resolver.getConfig(request);
        assertEquals(location, config.getLoginUrl());
    }

    @Test
    public void resolveWith_withSuccessUrlParameterShouldSucceed() {
        String location = "http://unit-test/api/saml/login?successUrl=42.nl/congrats";

        request.setParameter("successUrl", "42.nl/congrats");

        ResponseEntity<String> response = ResponseEntity.ok()
                .location(URI.create(location))
                .build();

        when(template.getForEntity("https://test-provider/sso/saml/login?successUrl=42.nl/congrats", String.class)).thenReturn(response);

        SAMLConfig config = resolver.getConfig(request);
        assertEquals(location, config.getLoginUrl());
    }

}
