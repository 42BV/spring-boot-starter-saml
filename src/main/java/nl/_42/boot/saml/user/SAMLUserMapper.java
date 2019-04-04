package nl._42.boot.saml.user;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface SAMLUserMapper {

    User load(SAMLUser authentication) throws UsernameNotFoundException;

}
