# Release notes

## UNRELEASED
Migrated from the outdated `spring-saml` and `open-saml` library to `one-login`, solving various OWASP issues.

- Some required properties were renamed:
  * `saml.metadata_url` => `saml.idp_metadata_url`
  * `saml.logout_url` => `saml.sp_logout_url`
- Some properties are no longer supported. Please use `saml.properties.<name>` when configuration is needed:
  * `saml.sp_strip_www`
  * `saml.response_skew`
  * `saml.max_authentication_age`
  * `saml.meta_data_trust_check`
  * `saml.in_response_check`
  * `saml.aliases`
- Property `saml.role_required` is now default false
- IDP certificate can now be configured directly, removing the need for a keystore

```yaml
saml:
  certificate: '
    -----BEGIN CERTIFICATE-----
    CONTENT
    -----END CERTIFICATE-----
  '
```

## 1.0.5 <23-10-2019>
- Added optional base 64 keystore option. Used when no `saml.keystore.file_name` defined.

```yaml
saml:
  keystore:
    base64: 'content'  
```

## 1.0.2 <07-05-2019>
- Added logging on role mappings
- Added option to allow users without roles. Roles are still required by default.

```yaml
saml:
  role_required: false
```

## 1.0.1 <07-05-2019>
- Added option to remove `www` from the service provider URL

```yaml
saml:
  sp_strip_www: true
```

## 1.0.0 <02-05-2019>
- Removed vulnerable transitive dependencies
    * Upgrade to Spring Boot `2.1.4.RELEASE`
    * Upgrade to Spring SAML `1.0.9.RELEASE`
- Production ready
