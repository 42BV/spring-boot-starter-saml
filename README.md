# Spring Boot Starter SAML

Library for integrating SAML (ADFS) authentication with Spring Boot / Security.

## Usage

Include the dependency in your Spring Boot application and configure:

```yaml
saml:
  idp_url: 'https://provider/idp/single-sign-on'
  metadata_url: 'https://provider/idp/metadata'
  sp_id: 'http://localhost'
  attributes:
    user: urn:oid:user
    role: urn:oid:role
  logout_url: /#/gone
  success_url: /#/dashboard
  expired_url: /#/expired
  forbidden_url: /#/forbidden
```

Additional configuration can also be supplied:

```yaml
saml:
  enabled: false
  metadata_trust_check: false
  rsa_signature_algorithm_uri: http://www.w3.org/2000/09/xmldsig#rsa-sha1
  sp_base_url: 'http://localhost/api'
  max_authentication_age: 9999
  session:
    timeout: 21600
  keystore:
    file_name: classpath:saml.jks
    key: 'myalias'
    user: 'somename'
    password: 'somepassword'
```
