package nl._42.boot.saml.user;

import org.springframework.security.core.userdetails.UserDetails;

public interface SAMLUserDecorator {

    UserDetails decorate(UserDetails details, SAMLResponse response);

}
