package nl._42.boot.saml.onelogin.user;

import com.onelogin.saml2.Auth;
import lombok.AllArgsConstructor;
import nl._42.boot.saml.user.SAMLAuthentication;
import nl._42.boot.saml.user.SAMLResponse;
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
        SAMLResponse response = new SAMLResponseImpl(auth);
        UserDetails details = userService.load(response);
        LocalDateTime expiration = convert(auth.getSessionExpiration());

        return new SAMLAuthentication(details, response, expiration);
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
