package nl._42.boot.saml.user;

import java.time.LocalDateTime;

public interface ExpiringAuthenticationToken {

    LocalDateTime getExpiration();

}
