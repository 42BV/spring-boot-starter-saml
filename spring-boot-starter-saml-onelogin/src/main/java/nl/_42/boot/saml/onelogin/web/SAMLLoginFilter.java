package nl._42.boot.saml.onelogin.web;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
public class SAMLLoginFilter extends AbstractSAMLFilter {

    private final String returnTo;

    @Setter
    private boolean forceAuthn;

    @Setter
    private boolean isPassive;

    @Setter
    private boolean setNameIdPolicy = true;

    public SAMLLoginFilter(Saml2Settings settings, String returnTo) {
        super(settings);
        this.returnTo = returnTo;
    }

    @Override
    protected void doFilter(Auth auth, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, SettingsException {
        String successUrl = request.getParameter("successUrl");
        if (StringUtils.isNotBlank(successUrl)) {
            HttpSession session = request.getSession();
            session.setAttribute(SAMLSuccessRedirectHandler.SUCCESS_URL_NAME, successUrl);
        }

        auth.login(returnTo, forceAuthn, isPassive, setNameIdPolicy);
    }

}
