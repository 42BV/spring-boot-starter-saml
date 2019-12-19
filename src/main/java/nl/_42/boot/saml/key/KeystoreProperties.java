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
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;

import java.util.Base64;
import java.util.Collections;
import java.util.Map;

/**
 * Wrapper of all keystore properties.
 *
 * @author Ailbert Riksen
 * @since dec 09, 2014
 */
@Data
@Slf4j
public class KeystoreProperties {

    public static final KeyManager EMPTY = new EmptyKeyManager();

    private static final DefaultResourceLoader RESOURCES = new DefaultResourceLoader();

    private String base64;

    private String fileName;

    private String user;

    private String password;

    private String key;

    /**
     * Build key manager.
     * @return the key manager
     */
    public KeyManager getKeyManager() {
        Resource resource = getResource();
        if (resource == null) {
            return EMPTY;
        }

        Map<String, String> passwords = Collections.singletonMap(user, password);
        return new JKSKeyManager(resource, password, passwords, key);
    }

    private Resource getResource() {
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

}
