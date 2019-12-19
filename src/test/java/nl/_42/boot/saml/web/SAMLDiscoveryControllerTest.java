/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.web;

import nl._42.boot.saml.AbstractWebTest;
import nl._42.boot.saml.SAMLProperties;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.mockito.Mockito.when;

public class SAMLDiscoveryControllerTest extends AbstractWebTest {

    @Mock
    private SAMLProperties properties;

    @Mock
    private MetadataManager metadata;

    @Before
    public void setUp() {
        initWebClient(new SAMLDiscoveryController(properties, metadata));
    }

    @Test
    public void ok() throws Exception {
        when(metadata.getIDPEntityNames()).thenReturn(Stream.of("a", "b", "c").collect(Collectors.toSet()));
        when(properties.getIdpUrl()).thenReturn("http://www.idp.com/login");

        this.webClient.perform(MockMvcRequestBuilders.get("/saml/idpSelection")
                .requestAttr("javax.servlet.forward.request_uri", "http://www.origin.com"))
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("/saml/login?idp=http://www.idp.com/login&idps=a&idps=b&idps=c"));
    }

    @Test
    public void no_forward() throws Exception {
        this.webClient.perform(MockMvcRequestBuilders.get("/saml/idpSelection"))
                .andExpect(MockMvcResultMatchers.status().isInternalServerError())
                .andExpect(MockMvcResultMatchers.jsonPath("error").value("Cannot directly access this service."));
    }

    @Test
    public void logged_in() throws Exception {
        this.webClient.perform(MockMvcRequestBuilders.get("/saml/idpSelection").principal(new UsernamePasswordAuthenticationToken("henk", "test")))
                .andExpect(MockMvcResultMatchers.status().isInternalServerError())
                .andExpect(MockMvcResultMatchers.jsonPath("error").value("User is already logged in."));
    }

}
