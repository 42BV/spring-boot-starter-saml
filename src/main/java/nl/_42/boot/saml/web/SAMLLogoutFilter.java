package nl._42.boot.saml.web;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.SAMLException;
import com.onelogin.saml2.settings.Saml2Settings;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SAMLLogoutFilter extends AbstractSAMLFilter {

    public SAMLLogoutFilter(Saml2Settings settings) {
        super(settings);
    }

    @Override
    protected void doFilter(Auth auth, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, SAMLException {
        auth.logout();
    }

}
