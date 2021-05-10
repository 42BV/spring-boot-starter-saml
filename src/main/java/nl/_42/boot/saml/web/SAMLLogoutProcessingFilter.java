package nl._42.boot.saml.web;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class SAMLLogoutProcessingFilter extends AbstractSAMLFilter {

    private final String successUrl;

    public SAMLLogoutProcessingFilter(Saml2Settings settings, String successUrl) {
        super(settings);
        this.successUrl = successUrl;
    }

    @Override
    protected void doFilter(Auth auth, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
        SecurityContextHolder.clearContext();
        log.info("Logout successful");

        response.sendRedirect(successUrl);
    }

}
