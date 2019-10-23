# Release notes

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
