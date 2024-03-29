/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.key.KeystoreProperties;
import nl._42.boot.saml.user.RoleMapper;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

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

    /**
     * Enables SAML authentication filters.
     */
    private boolean enabled;

    /**
     * IDP URL
     */
    private String idpUrl;

    /**
     * Metadata URL
     */
    private String metadataUrl;

    /**
     * Service provider ID
     */
    private String spId;

    /**
     * Service provider base URL
     */
    private String spBaseUrl;

    /**
     * Service provider base URL
     */
    private String spLoginUrl;

    /**
     * Strip 'www' from service provider return URL.
     */
    private boolean spStripWww;

    /**
     * Retrieve real service provider login URL, preventing a 302
     * redirect on the /saml/login URL on the browser.
     */
    private boolean skipLoginRedirect;

    /**
     * RSA signature algorithm, by default RSA SHA1.
     */
    private String rsaSignatureAlgorithmUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;

    /**
     * Keystore properties.
     */
    private KeystoreProperties keystore = new KeystoreProperties();

    /**
     * Maximum time from response creation when the message is deemed valid (in seconds).
     */
    private int responseSkew = 60;

    /**
     * Maximum authentication age.
     */
    private int maxAuthenticationAge = 9999;

    /**
     * Force new authentication upon login.
     */
    private boolean forceAuthN;

    /**
     * Check metadata trust upon login.
     */
    private boolean metaDataTrustCheck;

    /**
     * Verify the session is similar, fails during http to https redirect.
     * https://docs.spring.io/autorepo/docs/spring-security-saml/1.0.x/reference/html/chapter-troubleshooting.html#d5e1935
     */
    private boolean inResponseCheck;

    /**
     * Deny users with no roles.
     */
    private boolean roleRequired = true;

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
     * Session timeout.
     */
    private int sessionTimeout = 21600;

    /**
     * If cookies should be removed after a failed login attempt.
     */
    private boolean removeAllCookiesUponAuthenticationFailure = true;

    /**
     * Force principal.
     */
    private boolean forcePrincipal;

    /**
     * Redirect success URL.
     */
    private String successUrl = "/";

    /**
     * Redirect forbidden URL.
     */
    private String forbiddenUrl;

    /**
     * Redirect expired URL.
     */
    private String expiredUrl;

    /**
     * Redirect logout URL.
     */
    private String logoutUrl = "/";

    /**
     * URL aliases.
     */
    private Map<String, String> aliases = new HashMap<>();

    /**
     * Build a new role mapper.
     * @return the role mapper
     */
    public RoleMapper getRoleMapper() {
        if (!roles.isEmpty()) {
            log.info("Found 'saml.roles' in spring boot application properties.");
            roles.forEach((role, authority) -> log.info("\t {}: {}", role, authority));
        } else {
            log.warn("No 'saml.roles' found in spring boot application properties, no conversion of Crowd Groups will be applied!");
        }

        return new RoleMapper(roles);
    }

    /**
     * Validate that a certain property is defined.
     * @param value the current value
     * @param path the relative property path
     */
    public static void throwIfBlank(String value, String path) {
        if (StringUtils.isBlank(value)) {
            throw new IllegalStateException("Missing required SAML property 'saml." + path + ".");
        }
    }

}
