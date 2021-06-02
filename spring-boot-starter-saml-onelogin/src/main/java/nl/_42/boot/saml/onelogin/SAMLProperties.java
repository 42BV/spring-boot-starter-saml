/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.onelogin;

import com.onelogin.saml2.model.KeyStoreSettings;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.key.KeystoreProperties;
import nl._42.boot.saml.user.RoleMapper;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * SAML properties.
 *
 * @author Jeroen van Schagen
 * @since Oct 30, 2014
 */
@Data
@Slf4j
@ConfigurationProperties(prefix = "saml")
public class SAMLProperties {

    private static final String PROPERTY_PREFIX = "onelogin.saml2.";

    /**
     * Enables SAML authentication filters.
     */
    private boolean enabled;

    /**
     * IDP certificate
     */
    private String idpCertificate;

    /**
     * IDP logout URL
     */
    private String idpLogoutUrl;

    /**
     * IDP metadata URL
     */
    private String idpMetadataUrl;

    /**
     * IDP URL
     */
    private String idpUrl;

    /**
     * IDP validate
     */
    private boolean idpValidate = false;

    /**
     * Service provider ID
     */
    private String spId;

    /**
     * Service provider base URL
     */
    private String spBaseUrl = "";

    /**
     * Keystore properties.
     */
    private KeystoreProperties keystore = new KeystoreProperties();

    /**
     * Force new authentication upon login.
     */
    private boolean forceAuthN;

    /**
     * Deny users with no roles.
     */
    private boolean roleRequired;

    /**
     * Strict response validation.
     */
    private boolean strict = true;

    /**
     * Attribute mapping after successful authentication, requires a 'user'.
     */
    private Map<String, String> attributes = new HashMap<>();

    /**
     * Role mapping after successful login.
     */
    private Map<String, String> roles = new HashMap<>();

    /**
     * Assertions that should be matched.
     */
    private Map<String, String> assertions = new HashMap<>();

    /**
     * Custom properties that are set.
     */
    private Properties properties = new Properties();

    /**
     * Session timeout.
     */
    private int sessionTimeout = 21600;

    /**
     * If cookies should be removed after a failed login attempt.
     */
    private boolean removeAllCookiesUponAuthenticationFailure = true;

    /**
     * Retrieve real service provider login URL, preventing a 302
     * redirect on the /nl._42.boot.saml/login URL on the browser.
     */
    private boolean skipLoginRedirect;

    /**
     * Redirect success URL.
     */
    private String successUrl;

    /**
     * Redirect forbidden URL.
     */
    private String forbiddenUrl = "/forbidden";

    /**
     * Redirect expired URL.
     */
    private String expiredUrl = "/expired";

    /**
     * RSA signature algorithm, by default RSA SHA1.
     */
    private String rsaSignatureAlgorithmUri = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /**
     * Build a new role mapper.
     * @return the role mapper
     */
    public RoleMapper getRoleMapper() {
        if (!roles.isEmpty()) {
            log.info("Found 'nl._42.boot.saml.roles' in spring boot application properties.");
            roles.forEach((role, authority) -> log.info("\t {}: {}", role, authority));
        } else {
            log.warn("No 'nl._42.boot.saml.roles' found in spring boot application properties, no conversion of Crowd Groups will be applied!");
        }

        return new RoleMapper(roles);
    }

    public Saml2Settings build() {
        validate();

        KeyStoreSettings keyStoreSettings = buildKeystore();
        if (StringUtils.isBlank(idpCertificate)) {
            idpCertificate = getCertificate(keyStoreSettings);
        }

        SettingsBuilder builder = new SettingsBuilder();
        Map<String, Object> values = new HashMap<>();

        // Service provider properties
        values.put(SettingsBuilder.SP_ENTITYID_PROPERTY_KEY, spId);
        values.put(SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, buildSpUrl(SAMLAutoConfiguration.SSO_URL));
        values.put(SettingsBuilder.SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, buildSpUrl(SAMLAutoConfiguration.SLO_URL));

        // Identity provider properties
        values.put(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY, idpMetadataUrl);
        values.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, idpLogoutUrl);
        values.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        values.put(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY, idpUrl);
        values.put(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY, idpCertificate);

        values.put(SettingsBuilder.SECURITY_SIGNATURE_ALGORITHM, rsaSignatureAlgorithmUri);
        values.put(SettingsBuilder.STRICT_PROPERTY_KEY, strict);
        builder.fromValues(values, keyStoreSettings);

        Properties properties = buildProperties();
        builder.fromProperties(properties);

        Saml2Settings settings = builder.build();
        settings.setSPValidationOnly(!idpValidate);
        return settings;
    }

    public KeyStoreSettings buildKeystore() {
        try {
            KeyStore keyStore = keystore.getKeyStore();
            return new KeyStoreSettings(keyStore, keystore.getKey(), keystore.getPassword());
        } catch (Exception e) {
            throw new IllegalStateException("Could not instantiate keystore", e);
        }
    }

    public static final String getCertificate(KeyStoreSettings settings) {
        if (settings == null) {
            return null;
        }

        return KeystoreProperties.getCertificate(settings.getKeyStore(), settings.getSpAlias());
    }

    private Properties buildProperties() {
        Properties properties = new Properties();
        for (String name : this.properties.stringPropertyNames()) {
            properties.put(PROPERTY_PREFIX + name, this.properties.getProperty(name));
        }
        return properties;
    }

    private void validate() {
        throwIfBlank(getIdpMetadataUrl(), "idp_metadata_url");
        throwIfBlank(getIdpUrl(), "idp_url");
        throwIfBlank(getSpId(), "sp_id");
        throwIfBlank(getSpBaseUrl(), "sp_base_url");
    }

    private static void throwIfBlank(String value, String path) {
        if (StringUtils.isBlank(value)) {
            throw new IllegalStateException("Missing required SAML property 'nl._42.boot.saml." + path + ".");
        }
    }

    private String buildSpUrl(String path) {
        String url = StringUtils.stripEnd(spBaseUrl, "/");
        return url + path;
    }

}
