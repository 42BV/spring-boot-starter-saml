# Spring Boot Starter SAML

Library for integrating SAML (ADFS) authentication with Spring Boot / Security.

## Usage

Register beans and place in filter chain.

```java
@EnableSAML
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private MetadataGeneratorFilter samlMetadataGeneratorFilter;
    
    @Autowired
    private FilterChainProxy samlFilterChain;
    
    @Autowired
    private SAMLAuthenticationProvider samlAuthenticationProvider;
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
      auth.authenticationProvider(samlAuthenticationProvider);
    }
      
    @Override
    protected void configure(HttpSecurity http) {
      http.addFilterBefore(samlMetadataGeneratorFilter, BasicAuthenticationFilter.class);
      http.addFilterAfter(samlFilterChain, MetadataGeneratorFilter.class);
    }
    
}
```

Configuration:

```yaml
saml:
  idp_url: 'https://provider/idp/single-sign-on'
  metadata_url: 'https://provider/idp/metadata'
  metadata_trust_check: false
  sp_id: 'http://localhost'
  sp_base_url: 'http://localhost/api'
  rsa_signature_algorithm_uri: http://www.w3.org/2000/09/xmldsig#rsa-sha1
  max_authentication_age: 3600
  user_id_name: urn:oid:user
  display_name: urn:oid:name
  organisation_name: urn:oid:1.3.6.1.4.1.25178.1.2.9
  role_name: urn:oid:1.3.6.1.4.1.5923.1.1.1.1
  authorized_roles: 'employee,staff'
  authorized_organisations: 'a,b'
  logout_url: 'https://localhost/logout'
  success_url: /#/dashboard
  expired_url: /#/expired
  forbidden_url: /#/forbidden
  session:
    timeout: 21600
  keystore:
    file_name: classpath:saml.jks
    key: 'myalias'
    user: 'somename'
    password: 'somepassword'
```
