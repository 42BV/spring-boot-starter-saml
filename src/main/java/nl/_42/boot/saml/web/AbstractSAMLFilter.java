package nl._42.boot.saml.web;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.SAMLException;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@AllArgsConstructor
public abstract class AbstractSAMLFilter extends GenericFilterBean {

    private final Saml2Settings settings;

    @Override
    public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        try {
            Auth auth = new Auth(settings, httpServletRequest, httpServletResponse);
            doFilter(auth, httpServletRequest, httpServletResponse, chain);
        } catch (SAMLException se) {
            httpServletResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            log.error("Could perform authentication due to an unexpected error", se);
        }
    }

    protected abstract void doFilter(Auth auth, HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws IOException, ServletException, SAMLException;

}
