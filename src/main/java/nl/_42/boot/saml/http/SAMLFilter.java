package nl._42.boot.saml.http;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.List;

@Slf4j
public class SAMLFilter extends FilterChainProxy {

  public SAMLFilter(List<SecurityFilterChain> chains) {
    super(chains);
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    log.trace("Started SAML filter");
    super.doFilter(request, response, chain);
    log.trace("Ended SAML filter");
  }

}
