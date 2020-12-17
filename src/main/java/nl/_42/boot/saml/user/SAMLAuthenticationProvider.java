package nl._42.boot.saml.user;

import com.onelogin.saml2.Auth;
import lombok.AllArgsConstructor;
import org.joda.time.DateTime;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@AllArgsConstructor
public class SAMLAuthenticationProvider {

    private final SAMLUserService userService;

    public Authentication authenticate(Auth auth) throws AuthenticationException {
        SAMLResponse response = new SAMLResponse(auth);
        UserDetails details = userService.load(response);
        LocalDateTime expiration = convert(auth.getSessionExpiration());

        return new SAMLAuthentication(details, expiration);
    }

    private LocalDateTime convert(DateTime date) {
        if (date == null) {
            return null;
        }

        return LocalDateTime.of(
            date.getYear(),
            date.getMonthOfYear(),
            date.getDayOfMonth(),
            date.getHourOfDay(),
            date.getMinuteOfHour(),
            date.getSecondOfMinute()
        );
    }

}
