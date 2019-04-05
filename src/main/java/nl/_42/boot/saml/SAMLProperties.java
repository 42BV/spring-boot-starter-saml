/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml;

import lombok.Data;

import java.util.Properties;

/**
 * SAML properties.
 *
 * @author Jeroen van Schagen
 * @since Oct 30, 2014
 */
@Data
public class SAMLProperties {

    private String idpUrl;

    private String metaDataUrl;

    private String logoutUrl;

    private String serviceProviderId;

    private String serviceProviderBaseUrl;

    private String userAttribute;

    private String roleAttribute;

    private String rsaSignatureAlgorithmUri;

    private int maxAuthenticationAge;

    private boolean forceAuthN;

    private boolean metaDataTrustCheck;

    // Verify the session is similar, fails during http to https redirect
    // https://docs.spring.io/autorepo/docs/spring-security-saml/1.0.x/reference/html/chapter-troubleshooting.html#d5e1935
    private boolean inResponseCheck;



}
