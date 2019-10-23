/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.key;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
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

    private static final String BASE64_NAME   = "saml.keystore.base64";
    private static final String FILE_NAME     = "saml.keystore.file_name";
    private static final String USER_NAME     = "saml.keystore.user";
    private static final String PASSWORD_NAME = "saml.keystore.password";
    private static final String KEY_NAME      = "saml.keystore.key";

    private String base64;

    private String fileName;

    private String user;

    private String password;

    private String key;

    /**
     * Construct a new keystore properties based on an environment.
     * @param environment the environment
     * @return the properties
     */
    public static KeystoreProperties of(Environment environment) {
        KeystoreProperties properties = new KeystoreProperties();
        properties.setBase64(environment.getProperty(BASE64_NAME));
        properties.setFileName(environment.getProperty(FILE_NAME));
        properties.setUser(environment.getProperty(USER_NAME));
        properties.setPassword(environment.getProperty(PASSWORD_NAME));
        properties.setKey(environment.getProperty(KEY_NAME));
        return properties;
    }

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
