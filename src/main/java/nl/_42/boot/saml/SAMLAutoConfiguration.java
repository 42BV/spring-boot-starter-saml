package nl._42.boot.saml;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.config.SAMLConfigController;
import nl._42.boot.saml.user.SAMLUserService;
import nl._42.boot.saml.web.FriendlyURLComparator;
import nl._42.boot.saml.web.SAMLDefaultEntryPoint;
import nl._42.boot.saml.web.SAMLDiscoveryController;
import nl._42.boot.saml.web.SAMLFailureHandler;
import nl._42.boot.saml.web.SAMLFilter;
import nl._42.boot.saml.web.SAMLMetadataDisplayFilter;
import nl._42.boot.saml.web.SAMLMetadataGenerator;
import nl._42.boot.saml.web.SAMLSuccessRedirectHandler;
import nl._42.boot.saml.web.SAMLWebSSOProfile;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.storage.EmptyStorageFactory;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Timer;

import static nl._42.boot.saml.SAMLProperties.throwIfBlank;

/**
 * Enable SAML configuration.
 */
@Slf4j
@Configuration
@ComponentScan(basePackageClasses = SAMLConfigController.class)
public class SAMLAutoConfiguration {

    @Bean
    public SAMLProperties samlProperties() {
        return new SAMLProperties();
    }

    @Configuration
    @ComponentScan(basePackageClasses = SAMLDiscoveryController.class)
    @ConditionalOnProperty(name = "saml.enabled", havingValue = "true")
    public static class SAMLAuthenticationConfiguration {

        private final SAMLProperties properties;

        @Autowired
        public SAMLAuthenticationConfiguration(SAMLProperties properties) {
            throwIfBlank(properties.getIdpUrl(), "idp_url");
            throwIfBlank(properties.getMetadataUrl(), "metadata_url");
            throwIfBlank(properties.getSpId(), "sp_id");
            throwIfBlank(properties.getSpBaseUrl(), "sp_base_url");

            this.properties = properties;
        }

        @Bean
        public SAMLAuthenticationProvider samlAuthenticationProvider() {
            SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
            samlAuthenticationProvider.setUserDetails(samlUserDetailService());
            samlAuthenticationProvider.setForcePrincipalAsString(properties.isForcePrincipal());
            return samlAuthenticationProvider;
        }

        @Bean
        public SAMLUserDetailsService samlUserDetailService() {
            return new SAMLUserService(properties);
        }

        @Bean
        public MetadataGeneratorFilter samlMetadataGeneratorFilter() {
            return new MetadataGeneratorFilter(metadataGenerator());
        }

        @Bean
        public MetadataGenerator metadataGenerator() {
            SAMLMetadataGenerator generator = new SAMLMetadataGenerator();
            generator.setEntityId(properties.getSpId());
            generator.setEntityBaseURL(properties.getSpBaseUrl());
            generator.setSamlDiscovery(samlDiscovery());
            generator.setKeyManager(keyManager());

            // Only allow for 'post' binding by overriding the bindingsSSO getValue of the parent MetadataGenerator class.
            generator.setBindingsSSO(Arrays.asList("post"));
            return generator;
        }

        @Bean
        @Qualifier("metadata")
        public CachingMetadataManager metadata() throws MetadataProviderException {
            List<MetadataProvider> providers = new ArrayList<>();
            providers.add(metadataProvider());

            return new CachingMetadataManager(providers);
        }

        @Bean
        public MetadataProvider metadataProvider() throws MetadataProviderException {
            final Timer backgroundTaskTimer = new Timer(true);

            HTTPMetadataProvider provider = new HTTPMetadataProvider(backgroundTaskTimer, httpClient(), properties.getMetadataUrl());
            provider.setParserPool(parserPool());

            ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(provider);
            delegate.setMetadataTrustCheck(properties.isMetaDataTrustCheck());
            return delegate;
        }

        @Bean
        public StaticBasicParserPool parserPool() {
            StaticBasicParserPool pool = new StaticBasicParserPool();

            try {
                pool.initialize();
            } catch (XMLParserException e) {
                throw new IllegalStateException("Could not initialize parser pool", e);
            }

            return pool;
        }

        @Bean
        public ParserPoolHolder parserPoolHolder() {
            return new ParserPoolHolder();
        }

        @Bean
        public HttpClient httpClient() {
            return new HttpClient(multiThreadedHttpConnectionManager());
        }

        @Bean
        public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
            return new MultiThreadedHttpConnectionManager();
        }

        @Bean
        public SAMLContextProvider contextProvider() {
            SAMLContextProviderImpl provider = new SAMLContextProviderImpl();
            if (!properties.isInResponseCheck()) {
                provider.setStorageFactory(new EmptyStorageFactory());
            }
            return provider;
        }

        @Bean
        public static SAMLBootstrap samlBootstrap() {
            return new SAMLBootstrap();
        }

        @Bean
        public SAMLDefaultLogger samlLogger() {
            return new SAMLDefaultLogger();
        }

        @Bean
        public WebSSOProfileConsumer webSSOprofileConsumer() throws Exception {
            WebSSOProfileConsumerImpl webSSOProfileConsumerImpl = new WebSSOProfileConsumerImpl(processor(), metadata());
            webSSOProfileConsumerImpl.setMaxAuthenticationAge(properties.getMaxAuthenticationAge());
            webSSOProfileConsumerImpl.setResponseSkew(properties.getResponseSkew());
            webSSOProfileConsumerImpl.afterPropertiesSet();
            return webSSOProfileConsumerImpl;
        }

        @Bean
        public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() throws Exception {
            return buildConsumer();
        }

        @Bean
        public WebSSOProfile webSSOprofile() throws Exception {
            SAMLWebSSOProfile webSSOProfileImpl = new SAMLWebSSOProfile(processor(), metadata());
            webSSOProfileImpl.setStripWww(properties.isSpStripWww());
            webSSOProfileImpl.afterPropertiesSet();
            return webSSOProfileImpl;
        }

        @Bean
        public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() throws Exception {
            return buildConsumer();
        }

        private WebSSOProfileConsumerHoKImpl buildConsumer() throws Exception {
            WebSSOProfileConsumerHoKImpl consumer = new WebSSOProfileConsumerHoKImpl();
            consumer.setMetadata(metadata());
            consumer.setProcessor(processor());
            consumer.afterPropertiesSet();
            return consumer;
        }

        @Bean
        public WebSSOProfileECPImpl ecpprofile() throws Exception {
            WebSSOProfileECPImpl webSSOProfileECPImpl = new WebSSOProfileECPImpl();
            webSSOProfileECPImpl.setMetadata(metadata());
            webSSOProfileECPImpl.setProcessor(processor());
            webSSOProfileECPImpl.afterPropertiesSet();
            return webSSOProfileECPImpl;
        }

        @Bean
        public SingleLogoutProfile logoutProfile() throws Exception {
            SingleLogoutProfileImpl singleLogoutProfileImpl = new SingleLogoutProfileImpl();
            singleLogoutProfileImpl.setMetadata(metadata());
            singleLogoutProfileImpl.setProcessor(processor());
            singleLogoutProfileImpl.afterPropertiesSet();
            return singleLogoutProfileImpl;
        }

        @Bean
        public KeyManager keyManager() {
            return properties.getKeystore().getKeyManager();
        }

        @Bean
        public SAMLEntryPoint samlEntryPoint() {
            SAMLEntryPoint entry = new SAMLDefaultEntryPoint(new AntPathRequestMatcher("/saml/**"));
            entry.setFilterProcessesUrl("/saml/login");
            entry.setDefaultProfileOptions(defaultWebSSOProfileOptions());
            return entry;
        }

        @Bean
        public WebSSOProfileOptions defaultWebSSOProfileOptions() {
            WebSSOProfileOptions options = new WebSSOProfileOptions();
            options.setIncludeScoping(false);
            options.setForceAuthN(properties.isForceAuthN());
            return options;
        }

        @Bean
        public SAMLFilter samlFilterChain() {
            SAMLFilter chain = new SAMLFilter(samlMetadataGeneratorFilter());
            chain.on("/saml/login/**", samlEntryPoint());
            chain.on("/saml/logout/**", samlLogoutFilter());
            chain.on("/saml/metadata/**", samlMetadataDisplayFilter());
            chain.on("/saml/SSO/**", samlWebSSOProcessingFilter());
            chain.on("/saml/SSOHoK/**", samlWebSSOHoKProcessingFilter());
            chain.on("/saml/SingleLogout/**", samlLogoutProcessingFilter());
            chain.on("/saml/discovery/**", samlDiscovery());
            return chain;
        }

        @Bean
        public SAMLMetadataDisplayFilter samlMetadataDisplayFilter() {
            return new SAMLMetadataDisplayFilter(properties.getSpId());
        }

        @Bean
        public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() {
            SAMLWebSSOHoKProcessingFilter filter = new SAMLWebSSOHoKProcessingFilter();
            filter.setAuthenticationSuccessHandler(successRedirectHandler());
            filter.setAuthenticationManager(samlAuthenticationManager());
            filter.setAuthenticationFailureHandler(authenticationFailureHandler());
            return filter;
        }

        @Bean
        public SAMLProcessingFilter samlWebSSOProcessingFilter() {
            SAMLProcessingFilter filter = new SAMLProcessingFilter();
            filter.setAuthenticationManager(samlAuthenticationManager());
            filter.setAuthenticationSuccessHandler(successRedirectHandler());
            filter.setAuthenticationFailureHandler(authenticationFailureHandler());
            return filter;
        }

        private AuthenticationManager samlAuthenticationManager() {
            return new AuthenticationManagerAdapter(samlAuthenticationProvider());
        }

        @Bean
        public SAMLSuccessRedirectHandler successRedirectHandler() {
            return new SAMLSuccessRedirectHandler(properties);
        }

        @Bean
        public SAMLFailureHandler authenticationFailureHandler() {
            return new SAMLFailureHandler(properties);
        }

        @Bean
        public SAMLLogoutFilter samlLogoutFilter() {
            return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[] { logoutHandler() }, new LogoutHandler[] { logoutHandler() });
        }

        @Bean
        public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
            SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler();
            handler.setDefaultTargetUrl(properties.getLogoutUrl());
            return handler;
        }

        @Bean
        public SecurityContextLogoutHandler logoutHandler() {
            SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
            handler.setInvalidateHttpSession(true);
            handler.setClearAuthentication(true);
            return handler;
        }

        @Bean
        public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
            return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
        }

        @Bean
        public SAMLDiscovery samlDiscovery() {
            SAMLDiscovery discovery = new SAMLDiscovery();
            discovery.setIdpSelectionPath("/saml/idpSelection");
            return discovery;
        }

        @Bean
        public SAMLProcessor processor() throws Exception {
            return new SAMLProcessorImpl(Arrays.asList(redirectBinding(), httpPostBinding(), artifactBinding(), soapBinding(), paosBinding()));
        }

        @Bean
        public HTTPPostBinding httpPostBinding() {
            return new HTTPPostBinding(parserPool(), httpPostDecoder(), httpPostEncoder());
        }

        @Bean
        public HTTPPostDecoder httpPostDecoder() {
            HTTPPostDecoder decoder = new HTTPPostDecoder(parserPool());
            decoder.setURIComparator(new FriendlyURLComparator(properties.getAliases()));
            return decoder;
        }

        @Bean
        public HTTPPostEncoder httpPostEncoder() {
            return new HTTPPostEncoder(velocityEngine(), "/templates/saml2-post-binding.vm");
        }

        @Bean
        public VelocityEngine velocityEngine() {
            return VelocityFactory.getEngine();
        }

        @Bean
        public HTTPRedirectDeflateBinding redirectBinding() {
            return new HTTPRedirectDeflateBinding(parserPool());
        }

        @Bean
        public HTTPSOAP11Binding soapBinding() {
            return new HTTPSOAP11Binding(parserPool());
        }

        @Bean
        public HTTPPAOS11Binding paosBinding() {
            return new HTTPPAOS11Binding(parserPool());
        }

        @Bean
        public HTTPArtifactBinding artifactBinding() throws Exception {
            ArtifactResolutionProfileImpl profile = new ArtifactResolutionProfileImpl(httpClient());
            profile.setProcessor(new SAMLProcessorImpl(soapBinding()));
            profile.setMetadata(metadata());
            profile.afterPropertiesSet();
            return new HTTPArtifactBinding(parserPool(), velocityEngine(), profile);
        }

        @Bean
        public SAMLConfigListener samlConfigListener() {
            return new SAMLConfigListener(properties);
        }

        // Disable all sub-filters, these are included in the global SAML filter chain
        // This filter chains has guaranteed correct ordering

        @Bean
        public FilterRegistrationBean samlEntryPointRegistration(SAMLEntryPoint filter) {
            return disabledFilterRegistration(filter);
        }

        @Bean
        public FilterRegistrationBean samlMetadataGeneratorRegistration(MetadataGeneratorFilter filter) {
            return disabledFilterRegistration(filter);
        }

        @Bean
        public FilterRegistrationBean samlMetadataDisplayRegistration(MetadataDisplayFilter filter) {
            return disabledFilterRegistration(filter);
        }

        @Bean
        public FilterRegistrationBean samlWebSSOProcessingRegistration(SAMLWebSSOHoKProcessingFilter filter) {
            return disabledFilterRegistration(filter);
        }

        @Bean
        public FilterRegistrationBean samlLogoutRegistration(SAMLLogoutFilter filter) {
            return disabledFilterRegistration(filter);
        }

        @Bean
        public FilterRegistrationBean samlLogoutProcessingRegistration(SAMLLogoutProcessingFilter filter) {
            return disabledFilterRegistration(filter);
        }

        @Bean
        public FilterRegistrationBean samlDiscoveryRegistration(SAMLDiscovery filter) {
            return disabledFilterRegistration(filter);
        }

        private FilterRegistrationBean disabledFilterRegistration(Filter filter) {
            FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>(filter);
            registration.setEnabled(false);
            return registration;
        }

    }

    @Slf4j
    private static class SAMLConfigListener implements ApplicationListener<ContextRefreshedEvent> {

        private final SAMLProperties properties;

        public SAMLConfigListener(SAMLProperties properties) {
            this.properties = properties;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void onApplicationEvent(ContextRefreshedEvent event) {
            BasicSecurityConfiguration config = (BasicSecurityConfiguration) org.opensaml.Configuration.getGlobalSecurityConfiguration();
            config.registerSignatureAlgorithmURI("RSA", properties.getRsaSignatureAlgorithmUri());
            log.info("Registered RSA signature algorithm URI: {}", properties.getRsaSignatureAlgorithmUri());
        }

    }

    @AllArgsConstructor
    private static class AuthenticationManagerAdapter implements AuthenticationManager {

        private final AuthenticationProvider provider;

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            return provider.authenticate(authentication);
        }

    }

}
