/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.springsecurity.web;

import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.metadata.MetadataGenerator;

/**
 * SAML metadata generator with more setters.
 *
 * @author Jeroen van Schagen
 * @since Oct 30, 2014
 */
public class SAMLMetadataGenerator extends MetadataGenerator {
    
    public void setSamlDiscovery(SAMLDiscovery samlDiscovery) {
        this.samlDiscovery = samlDiscovery;
    }

}
