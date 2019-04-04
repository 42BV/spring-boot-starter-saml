/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.key;

import lombok.Data;

/**
 * Wrapper of all keystore properties.
 *
 * @author Ailbert Riksen
 * @since dec 09, 2014
 */
@Data
public class KeystoreProperties {

    private String fileName;

    private String user;

    private String password;

    private String key;

}
