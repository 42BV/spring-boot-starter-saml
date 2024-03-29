/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.web;

import nl._42.boot.saml.SAMLProperties;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Date;

/**
 * Session configuring success handler.
 *
 * @author Jeroen van Schagen
 * @since Apr 21, 2015
 */
public class SAMLSuccessRedirectHandler implements AuthenticationSuccessHandler {

    private final SAMLProperties properties;

    private RememberMeServices rememberMeServices;

    public SAMLSuccessRedirectHandler(SAMLProperties properties) {
        this.properties = properties;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (rememberMeServices != null) {
            rememberMeServices.loginSuccess(request, response, authentication);
        }

        HttpSession session = request.getSession();
        configureSession(session, authentication);
        
        String successUrl = (String) session.getAttribute(SAMLDefaultEntryPoint.SUCCESS_URL_SESSION_KEY);
        redirectTo(response, StringUtils.defaultIfBlank(successUrl, properties.getSuccessUrl()));
    }

    private void redirectTo(HttpServletResponse response, String location) {
        response.setHeader("Location", location);
        response.setStatus(HttpStatus.SEE_OTHER.value());
    }

    private void configureSession(HttpSession session, Authentication authentication) {
        int seconds = getSecondsToExpiration(authentication);
        session.setMaxInactiveInterval(seconds);
    }

    private int getSecondsToExpiration(Authentication authentication) {
        int seconds = properties.getSessionTimeout();
        if (authentication instanceof ExpiringUsernameAuthenticationToken) {
            Date expirationDate = ((ExpiringUsernameAuthenticationToken) authentication).getTokenExpiration();
            if (expirationDate != null) {
                seconds = getSecondsToExpiration(expirationDate);
            }
        }
        return Math.max(seconds, 0);
    }

    private int getSecondsToExpiration(Date expirationDate) {
        LocalDateTime currentTime = LocalDateTime.now();
        LocalDateTime expirationTime = LocalDateTime.ofInstant(expirationDate.toInstant(), ZoneId.systemDefault());
        return (int) (expirationTime.toEpochSecond(ZoneOffset.UTC) - currentTime.toEpochSecond(ZoneOffset.UTC));
    }

    @Autowired(required = false)
    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
    }

}
