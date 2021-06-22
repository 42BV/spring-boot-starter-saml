package nl._42.boot.saml.web;

import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.websso.WebSSOProfileImpl;

public class SAMLWebSSOProfile extends WebSSOProfileImpl {

  private boolean stripWww;

  public SAMLWebSSOProfile(SAMLProcessor processor, MetadataManager manager) {
    super(processor, manager);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void buildReturnAddress(AuthnRequest request, AssertionConsumerService service) throws MetadataProviderException {
    super.buildReturnAddress(request, service);

    if (stripWww) {
      String url = request.getAssertionConsumerServiceURL();
      String newUrl = url.replaceAll("www.", "");
      request.setAssertionConsumerServiceURL(newUrl);
    }
  }

  public void setStripWww(boolean stripWww) {
    this.stripWww = stripWww;
  }

}
