/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.onelogin.web;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.onelogin.SAMLProperties;
import nl._42.boot.saml.user.ExpiringAuthenticationToken;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * Session configuring success handler.
 *
 * @author Jeroen van Schagen
 * @since Apr 21, 2015
 */
@Slf4j
@AllArgsConstructor
public class SAMLSuccessRedirectHandler implements AuthenticationSuccessHandler {

    public static final String SUCCESS_URL_NAME = "successUrl";

    private final SAMLProperties properties;
    private final RememberMeServices rememberMeServices;

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

        String successUrl = getSuccessUrl(session);
        redirectTo(response, successUrl);
    }

    private String getSuccessUrl(HttpSession session) {
        String successUrl = (String) session.getAttribute(SUCCESS_URL_NAME);
        if (StringUtils.isBlank(successUrl) || successUrl.equals("/")) {
            successUrl = properties.getSuccessUrl();
        }

        return successUrl;
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
        if (authentication instanceof ExpiringAuthenticationToken) {
            LocalDateTime expiration = ((ExpiringAuthenticationToken) authentication).getExpiration();
            if (expiration != null) {
                seconds = getSecondsToExpiration(expiration);
            }
        }
        return Math.max(seconds, 0);
    }

    private int getSecondsToExpiration(LocalDateTime expiration) {
        LocalDateTime current = LocalDateTime.now();
        return (int) (expiration.toEpochSecond(ZoneOffset.UTC) - current.toEpochSecond(ZoneOffset.UTC));
    }

}
