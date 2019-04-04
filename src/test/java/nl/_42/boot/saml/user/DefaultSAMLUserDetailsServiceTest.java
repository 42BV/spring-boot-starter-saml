/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.user;

import nl._42.boot.saml.SAMLProperties;
import nl._42.boot.saml.UserNotAllowedException;
import nl._42.boot.saml.user.DefaultSAMLUserDetailsService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.SAMLCredential;

import java.util.Collections;
import java.util.List;
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
public class DefaultSAMLUserDetailsServiceTest {

    private DefaultSAMLUserDetailsService service;

    @Before
    public void setUp() {
        SAMLProperties properties = new SAMLProperties();
        properties.setUserIdName("user");
        properties.setDisplayName("name");
        properties.setRoleName("role");
        properties.setAuthorizedRoles("medewerker,externe");
        properties.setOrganisationName("organisation");
        properties.setAuthorizedOrganisations("vu, vorsen, wur");

        service = new DefaultSAMLUserDetailsService(properties, null);
    }

    @Test
    public void success_withChecks() {
        SAMLCredential credential = mock(SAMLCredential.class, RETURNS_DEEP_STUBS);
        GrantedAuthority authority = new SimpleGrantedAuthority("medewerker");

        when(credential.getAttribute("user").getAttributeValues()).thenReturn(toXmlObjects("henkid"));
        when(credential.getAttribute("name").getAttributeValues()).thenReturn(toXmlObjects("Henk Hendirksen"));
        when(credential.getAttribute("role").getAttributeValues()).thenReturn(toXmlObjects("medewerker"));
        when(credential.getAttribute("organisation").getAttributeValues()).thenReturn(toXmlObjects("vorsen"));

        User user = service.loadUserBySAML(credential);
        Assert.assertEquals("henkid", user.getUsername());
        Assert.assertEquals(Collections.singleton(authority), user.getAuthorities());
    }

    @Test
    public void success_noChecks() {
        SAMLCredential credential = mock(SAMLCredential.class, RETURNS_DEEP_STUBS);

        SAMLProperties properties = new SAMLProperties();
        properties.setUserIdName("user");
        properties.setDisplayName("name");
        properties.setRoleName("role");
        properties.setOrganisationName("organisation");
        properties.setAuthorizedRoles("");
        properties.setAuthorizedOrganisations("");

        service = new DefaultSAMLUserDetailsService(properties, null);

        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("guest");

        when(credential.getAttribute("user").getAttributeValues()).thenReturn(toXmlObjects("henkid"));
        when(credential.getAttribute("name").getAttributeValues()).thenReturn(toXmlObjects("Henk Hendirksen"));
        when(credential.getAttribute("organisation").getAttributeValues()).thenReturn(toXmlObjects());
        when(credential.getAttribute("role").getAttributeValues()).thenReturn(toXmlObjects("guest"));

        User user = service.loadUserBySAML(credential);
        Assert.assertEquals("henkid", user.getUsername());
        Assert.assertEquals(Collections.singleton(authority), user.getAuthorities());
    }

    @Test(expected = IllegalStateException.class)
    public void fail_missingUserId() {
        SAMLCredential credential = mock(SAMLCredential.class);
        Mockito.when(credential.getAttribute(Mockito.anyString())).thenReturn(null);

        service.loadUserBySAML(credential);
    }

    @Test(expected = IllegalStateException.class)
    public void fail_missingUserValue() {
        SAMLCredential credential = mock(SAMLCredential.class, RETURNS_DEEP_STUBS);
        when(credential.getAttribute(Mockito.anyString()).getAttributeValues()).thenReturn(toXmlObjects());

        service.loadUserBySAML(credential);
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_unauthorizedOrganisation() {
        SAMLCredential credential = mock(SAMLCredential.class, RETURNS_DEEP_STUBS);

        when(credential.getAttribute("user").getAttributeValues()).thenReturn(toXmlObjects("henkid"));
        when(credential.getAttribute("name").getAttributeValues()).thenReturn(toXmlObjects("Henk Hendirksen"));
        when(credential.getAttribute("organisation").getAttributeValues()).thenReturn(toXmlObjects("42"));
        when(credential.getAttribute("role").getAttributeValues()).thenReturn(toXmlObjects("medewerker"));

        service.loadUserBySAML(credential);
    }

    @Test(expected = UserNotAllowedException.class)
    public void fail_unauthorizedRole() {
        SAMLCredential credential = mock(SAMLCredential.class, RETURNS_DEEP_STUBS);

        when(credential.getAttribute("user").getAttributeValues()).thenReturn(toXmlObjects("henkid"));
        when(credential.getAttribute("name").getAttributeValues()).thenReturn(toXmlObjects("Henk Hendirksen"));
        when(credential.getAttribute("organisation").getAttributeValues()).thenReturn(toXmlObjects("vorsen"));
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
