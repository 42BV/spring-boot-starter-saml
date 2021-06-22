/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.springsecurity.web;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.UserNotAllowedException;
import nl._42.boot.saml.springsecurity.SAMLProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.stream.Stream;

@Slf4j
@AllArgsConstructor
public class SAMLFailureHandler implements AuthenticationFailureHandler {

    private final SAMLProperties properties;

    /**
     * {@inheritDoc}
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        String location = properties.getForbiddenUrl();

        if (exception instanceof UserNotAllowedException) {
            log.warn("Attempted to login with unauthorized role...", exception);
        } else {
            log.warn("Could not authenticate, clearing sessions and cookies...", exception);
            request.getSession().invalidate();
            SecurityContextHolder.getContext().setAuthentication(null);

            if (properties.isRemoveAllCookiesUponAuthenticationFailure()) {
                removeAllCookies(request, response);
            }

            location = properties.getExpiredUrl();
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
