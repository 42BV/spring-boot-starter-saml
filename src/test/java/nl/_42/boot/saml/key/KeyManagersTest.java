package nl._42.boot.saml.key;

import org.junit.Test;
import org.springframework.security.saml.key.KeyManager;

import static org.junit.Assert.assertEquals;

public class KeyManagersTest {

    @Test
    public void empty() {
        KeyManager keyManager = KeyManagers.build(new KeystoreProperties());
        assertEquals(KeyManagers.EMPTY, keyManager);
    }

}
