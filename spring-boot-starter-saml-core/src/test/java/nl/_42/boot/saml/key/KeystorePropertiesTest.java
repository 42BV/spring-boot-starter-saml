package nl._42.boot.saml.key;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyStore;

import static org.hamcrest.MatcherAssert.assertThat;

public class KeystorePropertiesTest {

    @Test
    public void build_shouldSucceed() {
        KeystoreProperties properties = properties();

        KeyStore keyStore = properties.getKeyStore();
        Assert.assertNotNull(keyStore);
    }

    @Test
    public void getCertificate_shouldSucceed() {
        KeystoreProperties properties = properties();
        KeyStore keyStore = properties.getKeyStore();

        String certificate = KeystoreProperties.getCertificate(keyStore, properties.getKey());
        assertThat(certificate, Matchers.startsWith("MIIDU"));
        assertThat(certificate, Matchers.endsWith("GuHE="));
    }

    @Test
    public void getCertificate_null_shouldSucceed() {
        String certificate = KeystoreProperties.getCertificate(null, "abc");
        Assert.assertEquals(null, certificate);
    }

    @Test
    public void getCertificate_empty_shouldSucceed() {
        KeystoreProperties properties = properties();
        KeyStore keyStore = properties.getKeyStore();

        String certificate = KeystoreProperties.getCertificate(keyStore, "");
        Assert.assertEquals(null, certificate);
    }

    private KeystoreProperties properties() {
        KeystoreProperties properties = new KeystoreProperties();
        properties.setKey("apollo");
        properties.setUser("apollo");
        properties.setPassword("nalle123");
        properties.setFileName("classpath:simple-saml.jks");
        return properties;
    }

}
