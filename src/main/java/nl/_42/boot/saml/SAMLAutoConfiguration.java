package nl._42.boot.saml;

import com.onelogin.saml2.settings.Saml2Settings;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.config.SAMLConfigController;
import nl._42.boot.saml.user.SAMLAuthenticationProvider;
import nl._42.boot.saml.user.SAMLUserService;
import nl._42.boot.saml.web.SAMLFailureHandler;
import nl._42.boot.saml.web.SAMLFilter;
import nl._42.boot.saml.web.SAMLLoginFilter;
import nl._42.boot.saml.web.SAMLLoginProcessingFilter;
import nl._42.boot.saml.web.SAMLLogoutFilter;
import nl._42.boot.saml.web.SAMLLogoutProcessingFilter;
import nl._42.boot.saml.web.SAMLMetadataDisplayFilter;
import nl._42.boot.saml.web.SAMLSuccessRedirectHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.web.authentication.RememberMeServices;

import java.util.Optional;

/**
 * Enable SAML configuration.
 */
@Slf4j
@Configuration
@ComponentScan(basePackageClasses = SAMLConfigController.class)
public class SAMLAutoConfiguration {

    static final String LOGIN_URL      = "/saml/login";
    static final String LOGOUT_URL     = "/saml/logout";
    static final String SSO_URL        = "/saml/SSO";
    static final String SLO_URL        = "/saml/SingleLogout";
    static final String METADATA_URL   = "/saml/metadata";

    @Bean
    public SAMLProperties samlProperties() {
        return new SAMLProperties();
    }

    @Configuration
    @AllArgsConstructor
    @ConditionalOnProperty(name = "saml.enabled", havingValue = "true")
    public static class SAMLAuthenticationConfiguration {

        private final SAMLProperties properties;

        @Lazy
        @Autowired
        private Optional<RememberMeServices> rememberMeServices;

        @Bean
        public Saml2Settings saml2Settings() {
            return properties.build();
        }

        // Web filters

        @Bean
        public SAMLFilter samlFilterChain(Saml2Settings settings) {
            SAMLFilter chain = new SAMLFilter();
            chain.on(LOGIN_URL, samlLoginFilter(settings));
            chain.on(LOGOUT_URL, samlLogoutFilter(settings));
            chain.on(SSO_URL, samlLoginProcessingFilter(settings));
            chain.on(SLO_URL, samlLogoutProcessingFilter(settings));
            chain.on(METADATA_URL, samlMetadataDisplayFilter(settings));
            return chain;
        }

        private SAMLLoginFilter samlLoginFilter(Saml2Settings settings) {
            SAMLLoginFilter filter = new SAMLLoginFilter(settings, SSO_URL);
            filter.setForceAuthn(properties.isForceAuthN());
            return filter;
        }

        private SAMLLoginProcessingFilter samlLoginProcessingFilter(Saml2Settings settings) {
            return new SAMLLoginProcessingFilter(
                settings,
                samlAuthenticationProvider(),
                samlSuccessRedirectHandler(),
                samlFailureHandler()
            );
        }

        private SAMLLogoutFilter samlLogoutFilter(Saml2Settings settings) {
            return new SAMLLogoutFilter(settings, SLO_URL);
        }

        private SAMLLogoutProcessingFilter samlLogoutProcessingFilter(Saml2Settings settings) {
            return new SAMLLogoutProcessingFilter(settings, properties.getSuccessUrl());
        }

        private SAMLMetadataDisplayFilter samlMetadataDisplayFilter(Saml2Settings settings) {
            return new SAMLMetadataDisplayFilter(
                settings,
                properties.getSpId(),
                properties.getIdpMetadataUrl()
            );
        }

        // Authentication

        @Bean
        public SAMLAuthenticationProvider samlAuthenticationProvider() {
            return new SAMLAuthenticationProvider(samlUserService());
        }

        @Bean
        public SAMLUserService samlUserService() {
            return new SAMLUserService(properties);
        }

        @Bean
        public SAMLSuccessRedirectHandler samlSuccessRedirectHandler() {
            return new SAMLSuccessRedirectHandler(
                properties,
                rememberMeServices.orElse(null)
            );
        }

        @Bean
        public SAMLFailureHandler samlFailureHandler() {
            return new SAMLFailureHandler(properties);
        }

    }

}
