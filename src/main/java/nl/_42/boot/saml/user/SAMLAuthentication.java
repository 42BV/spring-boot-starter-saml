package nl._42.boot.saml.user;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;

public class SAMLAuthentication extends UsernamePasswordAuthenticationToken implements ExpiringAuthenticationToken {

    private final LocalDateTime expiration;

    public SAMLAuthentication(UserDetails details, LocalDateTime expiration) {
        super(
            details.getUsername(),
            details.getPassword(),
            details.getAuthorities()
        );

        this.expiration = expiration;
    }

    @Override
    public LocalDateTime getExpiration() {
        return expiration;
    }

}
