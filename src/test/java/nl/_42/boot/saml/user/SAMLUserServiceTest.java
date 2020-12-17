/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.user;

import nl._42.boot.saml.AbstractApplicationTest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.internal.util.collections.Sets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Optional;

import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SAMLUserServiceTest extends AbstractApplicationTest {

    @Autowired
    private SAMLUserService service;

    private SAMLResponse response;

    @Before
    public void setUp() {
        response = mock(SAMLResponse.class, RETURNS_DEEP_STUBS);
    }

    @Test
    public void success() {
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");

        when(response.getValue("urn:oid:user")).thenReturn(Optional.of("henkid"));
        when(response.getValues("urn:oid:role")).thenReturn(Sets.newSet("medewerker", "unknown"));
        when(response.getValues("urn:oid:organisation")).thenReturn(Sets.newSet("vorsen.nl"));

        UserDetails user = service.load(response);

        Assert.assertEquals("henkid", user.getUsername());
        Assert.assertEquals(Collections.singleton(authority), user.getAuthorities());
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_missingUserId() {
        when(response.getValues(Mockito.anyString())).thenReturn(null);

        service.load(response);
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_missingUserValue() {
        when(response.getValues(Mockito.anyString())).thenReturn(Sets.newSet());
        when(response.getValues("urn:oid:organisation")).thenReturn(Sets.newSet("vorsen.nl"));

        service.load(response);
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_unauthorizedRole() {
        when(response.getValues(Mockito.anyString())).thenReturn(Sets.newSet());
        when(response.getValues("user")).thenReturn(Sets.newSet("henkid"));
        when(response.getValues("name")).thenReturn(Sets.newSet("Henk Hendirksen"));
        when(response.getValues("role")).thenReturn(Sets.newSet("student"));

        service.load(response);
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_unauthorizedOrganisation() {
        when(response.getValues("urn:oid:user")).thenReturn(Sets.newSet("henkid"));
        when(response.getValues("urn:oid:role")).thenReturn(Sets.newSet("medewerker", "unknown"));
        when(response.getValues("urn:oid:organisation")).thenReturn(Sets.newSet("microsoft.com"));

        service.load(response);
    }

}
