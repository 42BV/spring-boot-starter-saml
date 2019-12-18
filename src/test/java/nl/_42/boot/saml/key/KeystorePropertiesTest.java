package nl._42.boot.saml.key;

import nl._42.boot.saml.AbstractApplicationTest;
import nl._42.boot.saml.SAMLProperties;
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
    private SAMLProperties context;

    private KeystoreProperties original;
    private KeystoreProperties current;

    @Before
    public void setUp() {
        original = context.getKeystore();
        current = new KeystoreProperties();
    }

    @Test
    public void empty() {
        KeyManager keyManager = current.getKeyManager();
        assertEquals(KeystoreProperties.EMPTY, keyManager);
    }

    @Test
    public void file() {
        current.setFileName(original.getFileName());
        current.setKey(original.getKey());
        current.setUser(original.getUser());
        current.setPassword(original.getPassword());

        PublicKey original = getPublicKey(this.original);
        PublicKey created = getPublicKey(current);

        assertNotNull(created);
        assertEquals(original, created);
    }

    @Test
    public void base64() {
        current.setBase64(original.getBase64());
        current.setKey(original.getKey());
        current.setUser(original.getUser());
        current.setPassword(original.getPassword());

        PublicKey original = getPublicKey(this.original);
        PublicKey created = getPublicKey(current);

        assertNotNull(created);
        assertEquals(original, created);
    }

    private PublicKey getPublicKey(KeystoreProperties properties) {
        JKSKeyManager keyManager = (JKSKeyManager) properties.getKeyManager();
        return keyManager.getPublicKey(original.getKey());
    }

}
