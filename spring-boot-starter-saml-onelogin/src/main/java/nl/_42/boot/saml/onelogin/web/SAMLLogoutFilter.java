package nl._42.boot.saml.onelogin.web;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.SAMLException;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class SAMLLogoutFilter extends AbstractSAMLFilter {

    private final String returnTo;

    public SAMLLogoutFilter(Saml2Settings settings, String returnTo) {
        super(settings);
        this.returnTo = returnTo;
    }

    @Override
    protected void doFilter(Auth auth, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, SAMLException {
        auth.logout(returnTo);
    }

}