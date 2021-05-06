package nl._42.boot.saml.web;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.SAMLException;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.user.SAMLAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class SAMLProcessingFilter extends AbstractSAMLFilter {

    private final SAMLAuthenticationProvider authenticationProvider;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    public SAMLProcessingFilter(
        Saml2Settings settings,
        SAMLAuthenticationProvider authenticationProvider,
        AuthenticationSuccessHandler successHandler,
        AuthenticationFailureHandler failureHandler
    ) {
        super(settings);

        this.authenticationProvider = authenticationProvider;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    @Override
    protected void doFilter(Auth auth, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException, SAMLException {
        try {
            auth.processResponse();
        } catch (Exception e) {
            throw new SAMLException("Could not process response", e);
        }

        if (auth.isAuthenticated()) {
            handleSuccess(auth, request, response);
        } else {
            handleFailure(auth, request, response);
        }
    }

    private void handleSuccess(Auth auth, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        Authentication authentication = authenticationProvider.authenticate(auth);
        log.info("Authentication {} successful", authentication.getName());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    private void handleFailure(Auth auth, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String message = String.format("Could not authenticate: (%s) %s", auth.getLastErrorReason(), String.join(", ", auth.getErrors()));
        failureHandler.onAuthenticationFailure(request, response, new AuthenticationServiceException(message));
    }

}
