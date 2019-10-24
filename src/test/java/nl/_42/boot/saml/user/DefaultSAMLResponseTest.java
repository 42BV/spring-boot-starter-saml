package nl._42.boot.saml.user;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.springframework.security.saml.SAMLCredential;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class DefaultSAMLResponseTest {

  private DefaultSAMLResponse response;
  private SAMLCredential credential;

  @Before
  public void setUp() {
    credential = Mockito.mock(SAMLCredential.class);
    response = new DefaultSAMLResponse(credential);
  }

  @Test
  public void getValue_string() {
    Attribute attribute = Mockito.mock(Attribute.class);
    XSString string = Mockito.mock(XSString.class);
    Mockito.when(credential.getAttribute("uid")).thenReturn(attribute);
    Mockito.when(attribute.getAttributeValues()).thenReturn(Arrays.asList(string));
    Mockito.when(string.getValue()).thenReturn("jan");

    String uid = response.getValue("uid").orElse("");
    assertEquals("jan", uid);
  }

  @Test
  public void getValue_any() {
    Attribute attribute = Mockito.mock(Attribute.class);
    XSAny any = Mockito.mock(XSAny.class);
    Mockito.when(credential.getAttribute("uid")).thenReturn(attribute);
    Mockito.when(attribute.getAttributeValues()).thenReturn(Arrays.asList(any));
    Mockito.when(any.getTextContent()).thenReturn("jan");

    String uid = response.getValue("uid").orElse("");
    assertEquals("jan", uid);
  }

  @Test
  public void getValue_any_null() {
    Attribute attribute = Mockito.mock(Attribute.class);
    XSAny any = Mockito.mock(XSAny.class);
    Mockito.when(credential.getAttribute("uid")).thenReturn(attribute);
    Mockito.when(attribute.getAttributeValues()).thenReturn(Arrays.asList(any));

    String uid = response.getValue("uid").orElse("");
    assertEquals("", uid);
  }

  @Test
  public void getValue_null() {
    String uid = response.getValue("uid").orElse("");
    assertEquals("", uid);
  }

}
