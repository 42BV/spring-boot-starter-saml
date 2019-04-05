package nl._42.boot.saml.user;

import org.springframework.security.core.userdetails.User;

public interface SAMLUserDecorator {

    User decorate(User user, SAMLResponse response);

}
