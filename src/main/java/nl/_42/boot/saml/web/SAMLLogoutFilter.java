package nl._42.boot.saml.web;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.SAMLException;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class SAMLLogoutFilter extends AbstractSAMLFilter {

    private static final String SAML_RESPONSE = "SAMLResponse";

    private final String successUrl;

    public SAMLLogoutFilter(Saml2Settings settings, String successUrl) {
        super(settings);
        this.successUrl = successUrl;
    }

    @Override
    protected void doFilter(Auth auth, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, SAMLException {
        if (isSuccess(request)) {
            SecurityContextHolder.clearContext();
            response.sendRedirect(successUrl);
        } else {
            auth.logout();
        }
    }

    private boolean isSuccess(HttpServletRequest request) {
        String response = request.getParameter(SAML_RESPONSE);
        return StringUtils.isNotBlank(response);
    }

}
