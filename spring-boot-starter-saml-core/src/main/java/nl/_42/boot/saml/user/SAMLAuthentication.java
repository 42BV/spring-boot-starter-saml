package nl._42.boot.saml.user;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;

public class SAMLAuthentication extends UsernamePasswordAuthenticationToken implements ExpiringAuthenticationToken {

    private final SAMLResponse response;
    private final LocalDateTime expiration;

    public SAMLAuthentication(UserDetails details, SAMLResponse response, LocalDateTime expiration) {
        super(
            details,
            details.getPassword(),
            details.getAuthorities()
        );

        this.response = response;
        this.expiration = expiration;
    }

    public SAMLResponse getResponse() {
        return response;
    }

    @Override
    public LocalDateTime getExpiration() {
        return expiration;
    }

}
