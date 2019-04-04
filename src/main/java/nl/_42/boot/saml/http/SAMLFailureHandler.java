/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.http;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.UserNotAllowedException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * 
 *
 * @author Jeroen van Schagen
 * @since Apr 28, 2015
 */
@Slf4j
public class SAMLFailureHandler implements AuthenticationFailureHandler {

    @Setter
    private String forbiddenUrl;
    
    @Setter
    private String expiredUrl;

    @Setter
    private boolean removeAllCookiesUponAuthenticationFailure;

    /**
     * {@inheritDoc}
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        String location = forbiddenUrl;

        if (exception instanceof UserNotAllowedException) {
            log.warn("Attempted to login with unauthorized role...", exception);
        } else {
            log.warn("Could not authenticate, clearing sessions and cookies...", exception);
            request.getSession().invalidate();
            SecurityContextHolder.getContext().setAuthentication(null);

            if (removeAllCookiesUponAuthenticationFailure) {
                removeAllCookies(request, response);
            }

            location = expiredUrl;
        }

        redirectTo(response, location);
    }
    
    private void redirectTo(HttpServletResponse response, String location) {
        response.setHeader("Location", location);
        response.setStatus(HttpStatus.SEE_OTHER.value());
    }

    private void removeAllCookies(HttpServletRequest request, HttpServletResponse response) {
        getCookies(request).forEach(cookie -> {
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        });
    }

    private Stream<Cookie> getCookies(HttpServletRequest request) {
        return Optional.ofNullable(request.getCookies()).map(Stream::of).orElseGet(Stream::empty);
    }

}
