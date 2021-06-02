/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.key;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Base64;

/**
 * Wrapper of all keystore properties.
 *
 * @author Ailbert Riksen
 * @since dec 09, 2014
 */
@Data
@Slf4j
public class KeystoreProperties {

    private static final DefaultResourceLoader RESOURCES = new DefaultResourceLoader();

    private String base64;

    private String fileName;

    private String user;

    private String password;

    private String key;

    public KeyStore getKeyStore() {
        Resource resource = getResource();
        if (resource == null) {
            return null;
        }

        return getKeyStore(resource);
    }

    private KeyStore getKeyStore(Resource resource) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(resource.getInputStream(), password.toCharArray());
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new IllegalStateException("Could not instantiate keystore", e);
        }
    }

    public Resource getResource() {
        Resource resource = null;
        if (StringUtils.isNotBlank(fileName)) {
            resource = RESOURCES.getResource(fileName);
            log.info("SAML keystore found from file.");
        } else if (StringUtils.isNotBlank(base64)) {
            byte[] content = Base64.getDecoder().decode(base64);
            resource = new ByteArrayResource(content);
            log.info("SAML keystore found in encoded Base64 string.");
        }
        return resource;
    }

    public static final String getCertificate(KeyStore keyStore, String alias) {
        if (keyStore == null || StringUtils.isEmpty(alias)) {
            return null;
        }

        try {
            Certificate certificate = keyStore.getCertificate(alias);
            return getContents(certificate);
        } catch (KeyStoreException kse) {
            throw new IllegalStateException("Could not retrieve certificate", kse);
        }
    }

    private static String getContents(Certificate certificate) {
        if (certificate == null) {
            return null;
        }

        try {
            byte[] contents = certificate.getEncoded();
            return Base64.getEncoder().encodeToString(contents);
        } catch (CertificateEncodingException cee) {
            throw new IllegalStateException("Could not retrieve certificate", cee);
        }
    }

}
