package nl._42.boot.saml.web;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SAMLMetadataDisplayFilterTest {

  @Test
  public void getMetadataFileName_shouldSucceed_withProvider() {
    String fileName = SAMLMetadataDisplayFilter.getMetadataFileName("https://demo.ascme.nl/v2");
    assertEquals("demo_ascme_nl_v2_metadata.xml", fileName);
  }

  @Test
  public void getMetadataFileName_shouldSucceed_withoutProvider() {
    String fileName = SAMLMetadataDisplayFilter.getMetadataFileName(" ");
    assertEquals("spring_saml_metadata.xml", fileName);
  }

}
