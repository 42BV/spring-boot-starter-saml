package nl._42.boot.saml.user;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.stream.Collectors;

public class DefaultSAMLUserMapper implements SAMLUserMapper {

    @Override
    public User load(SAMLUser authentication) throws UsernameNotFoundException {
        Collection<SimpleGrantedAuthority> authorities = authentication.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new User(authentication.getUserId(), "", authorities);
    }

}
