package nl._42.boot.saml.key;

import com.onelogin.saml2.model.KeyStoreSettings;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;

public class KeystorePropertiesTest {

    @Test
    public void build_shouldSucceed() {
        KeystoreProperties properties = properties();

        KeyStoreSettings settings = properties.build();
        Assert.assertNotNull(settings.getKeyStore());
        Assert.assertEquals(properties.getKey(), settings.getSpAlias());
        Assert.assertEquals(properties.getPassword(), settings.getSpKeyPass());
    }

    @Test
    public void getCertificate_shouldSucceed() {
        KeyStoreSettings settings = properties().build();

        String certificate = KeystoreProperties.getCertificate(settings);
        assertThat(certificate, Matchers.startsWith("MIIDU"));
        assertThat(certificate, Matchers.endsWith("GuHE="));
    }

    @Test
    public void getCertificate_null_shouldSucceed() {
        String certificate = KeystoreProperties.getCertificate(null);
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
