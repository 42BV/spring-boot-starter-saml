/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.user;

import nl._42.boot.saml.AbstractApplicationTest;
import nl._42.boot.saml.UserNotAllowedException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLCredential;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SAMLUserServiceTest extends AbstractApplicationTest {

    @Autowired
    private SAMLUserService service;

    private SAMLCredential credential;

    @Before
    public void setUp() {
        credential = mock(SAMLCredential.class, RETURNS_DEEP_STUBS);
    }

    @Test
    public void success() {
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");

        when(credential.getAttribute("urn:oid:user").getAttributeValues()).thenReturn(toXmlObjects("henkid"));
        when(credential.getAttribute("urn:oid:role").getAttributeValues()).thenReturn(toXmlObjects("medewerker", "unknown"));
        when(credential.getAttribute("urn:oid:organisation").getAttributeValues()).thenReturn(toXmlObjects("vorsen.nl"));

        UserDetails user = service.loadUserBySAML(credential);

        Assert.assertEquals("henkid", user.getUsername());
        Assert.assertEquals(Collections.singleton(authority), user.getAuthorities());
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_missingUserId() {
        when(credential.getAttribute(Mockito.anyString())).thenReturn(null);

        service.loadUserBySAML(credential);
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_missingUserValue() {
        when(credential.getAttribute(Mockito.anyString()).getAttributeValues()).thenReturn(toXmlObjects());

        when(credential.getAttribute("urn:oid:organisation").getAttributeValues()).thenReturn(toXmlObjects("vorsen.nl"));

        service.loadUserBySAML(credential);
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_unauthorizedRole() {
        when(credential.getAttribute(Mockito.anyString()).getAttributeValues()).thenReturn(toXmlObjects());

        when(credential.getAttribute("user").getAttributeValues()).thenReturn(toXmlObjects("henkid"));
        when(credential.getAttribute("name").getAttributeValues()).thenReturn(toXmlObjects("Henk Hendirksen"));
        when(credential.getAttribute("role").getAttributeValues()).thenReturn(toXmlObjects("student"));

        service.loadUserBySAML(credential);
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_unauthorizedOrganisation() {
        when(credential.getAttribute("urn:oid:user").getAttributeValues()).thenReturn(toXmlObjects("henkid"));
        when(credential.getAttribute("urn:oid:role").getAttributeValues()).thenReturn(toXmlObjects("medewerker", "unknown"));
        when(credential.getAttribute("urn:oid:organisation").getAttributeValues()).thenReturn(toXmlObjects("microsoft.com"));

        service.loadUserBySAML(credential);
    }

    private List<XMLObject> toXmlObjects(String... values) {
        return Stream.of(values).map(SimpleXMLString::new).collect(Collectors.toList());
    }

    private static class SimpleXMLString extends XSStringImpl {

        SimpleXMLString(String value) {
            super("", "", "");
            setValue(value);
        }

    }

}
