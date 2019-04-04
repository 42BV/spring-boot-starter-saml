# Spring Boot Starter SAML

Library for integrating SAML (ADFS) authentication with Spring Boot / Security.

## Usage

Register beans and place in filter chain.

```java
@EnableSAML
@Configuration
@Conditional(SAMLEnabledCondition.class)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private MetadataGeneratorFilter samlMetadataGeneratorFilter;
    
    @Autowired
    private FilterChainProxy samlFilterChain;
    
    @Override
    protected void configure(HttpSecurity http) {
      http.addFilterBefore(samlMetadataGeneratorFilter, BasicAuthenticationFilter.class);
      http.addFilterAfter(samlFilterChain, MetadataGeneratorFilter.class);
    }
    
}
```

Required configuration:

```yaml
saml:
  idp_url: 'https://provider/idp/single-sign-on'
  metadata_url: 'https://provider/idp/metadata'
  sp_id: 'http://localhost'
  sp_base_url: 'http://localhost/api'
  user_id_name: urn:oid:user
  logout_url: /#/gone
  success_url: /#/dashboard
  expired_url: /#/expired
  forbidden_url: /#/forbidden
  keystore:
    file_name: classpath:saml.jks
    key: 'myalias'
    user: 'somename'
    password: 'somepassword'
```

Additional (optional) configuration:

```yaml
saml:
  enabled: false
  metadata_trust_check: false
  rsa_signature_algorithm_uri: http://www.w3.org/2000/09/xmldsig#rsa-sha1
  max_authentication_age: 9999
  display_name: urn:oid:name
  role_name: urn:oid:role
  session:
    timeout: 21600
  keystore:
    file_name: classpath:saml.jks
    key: 'myalias'
    user: 'somename'
    password: 'somepassword'
```
