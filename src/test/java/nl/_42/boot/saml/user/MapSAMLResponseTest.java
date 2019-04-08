package nl._42.boot.saml.user;

import org.junit.Before;
import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertEquals;

public class MapSAMLResponseTest {

    private MapSAMLResponse response;

    @Before
    public void setUp() {
        response = new MapSAMLResponse();
    }

    @Test
    public void empty() {
        assertEquals(0, response.getValues("user").size());
        assertEquals(false, response.getValue("user").isPresent());
    }

    @Test
    public void found_one() {
        response.put("user", "henk");

        assertEquals(Collections.singleton("henk"), response.getValues("user"));
        assertEquals("henk", response.getValue("user").get());
    }

    @Test
    public void found_multiple() {
        response.put("user", "henk");
        response.put("roles", "admin", "manager");
        response.put("name", "Henk de Boer");

        assertEquals(2, response.getValues("roles").size());
        assertEquals("admin", response.getValue("roles").get());
    }

}
