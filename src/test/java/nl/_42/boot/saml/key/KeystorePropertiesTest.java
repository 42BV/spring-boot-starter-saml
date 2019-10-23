package nl._42.boot.saml.key;

import nl._42.boot.saml.AbstractApplicationTest;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;

import java.security.PublicKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class KeystorePropertiesTest extends AbstractApplicationTest {

    @Autowired
    private KeystoreProperties base;

    private KeystoreProperties properties;

    @Before
    public void setUp() {
        properties = new KeystoreProperties();
    }

    @Test
    public void empty() {
        KeyManager keyManager = properties.getKeyManager();
        assertEquals(KeystoreProperties.EMPTY, keyManager);
    }

    @Test
    public void file() {
        properties.setFileName(base.getFileName());
        properties.setKey(base.getKey());
        properties.setUser(base.getUser());
        properties.setPassword(base.getPassword());

        PublicKey original = getPublicKey(base);
        PublicKey created = getPublicKey(properties);

        assertNotNull(created);
        assertEquals(original, created);
    }

    @Test
    public void base64() {
        properties.setBase64(base.getBase64());
        properties.setKey(base.getKey());
        properties.setUser(base.getUser());
        properties.setPassword(base.getPassword());

        PublicKey original = getPublicKey(base);
        PublicKey created = getPublicKey(properties);

        assertNotNull(created);
        assertEquals(original, created);
    }

    private PublicKey getPublicKey(KeystoreProperties properties) {
        JKSKeyManager keyManager = (JKSKeyManager) properties.getKeyManager();
        return keyManager.getPublicKey(base.getKey());
    }

}
