/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.user;

import nl._42.boot.saml.SAMLProperties;
import nl._42.boot.saml.UserNotAllowedException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLCredential;

import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 *
 *
 * @author jeroen
 * @since Oct 31, 2014
 */
@RunWith(MockitoJUnitRunner.class)
public class SAMLUserServiceTest {

    private SAMLUserService service;
    private SAMLCredential credential;
    private Properties roles;

    @Before
    public void setUp() {
        SAMLProperties properties = new SAMLProperties();
        properties.setUserAttribute("user");
        properties.setRoleAttribute("role");

        roles = new Properties();
        roles.put("medewerker", "ROLE_USER");

        credential = mock(SAMLCredential.class, RETURNS_DEEP_STUBS);
        service = new SAMLUserService(properties, new RoleMapper(roles));
    }

    @Test
    public void success() {
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");

        when(credential.getAttribute("user").getAttributeValues()).thenReturn(toXmlObjects("henkid"));
        when(credential.getAttribute("role").getAttributeValues()).thenReturn(toXmlObjects("medewerker", "unknown"));

        UserDetails user = service.loadUserBySAML(credential);
        Assert.assertEquals("henkid", user.getUsername());
        Assert.assertEquals(Collections.singleton(authority), user.getAuthorities());
    }

    @Test(expected = IllegalStateException.class)
    public void fail_missingUserId() {
        Mockito.when(credential.getAttribute(Mockito.anyString())).thenReturn(null);

        service.loadUserBySAML(credential);
    }

    @Test(expected = IllegalStateException.class)
    public void fail_missingUserValue() {
        when(credential.getAttribute(Mockito.anyString()).getAttributeValues()).thenReturn(toXmlObjects());

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
