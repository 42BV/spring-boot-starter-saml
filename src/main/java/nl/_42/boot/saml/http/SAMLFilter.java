package nl._42.boot.saml.http;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class SAMLFilter extends GenericFilterBean {

  private List<SecurityFilterChain> chains = new ArrayList<>();

  public void register(String url, Filter filter) {
    AntPathRequestMatcher matcher = new AntPathRequestMatcher(url);
    chains.add(new DefaultSecurityFilterChain(matcher, filter));
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    List<Filter> filters = getFilters(httpServletRequest);

    if (filters.isEmpty()) {
      // Not a SAML request, continue on regular chain
      chain.doFilter(request, response);
    } else {
      // Detected SAML request, invoke internal handlers
      handle(request, response, filters, chain);
    }
  }

  private void handle(ServletRequest request, ServletResponse response, List<Filter> filters, FilterChain chain) throws IOException, ServletException {
    log.trace("Started SAML filter");

    for (Filter filter : filters) {
      filter.doFilter(request, response, chain);
    }

    log.trace("Ended SAML filter");
  }

  private List<Filter> getFilters(HttpServletRequest request) {
    List<Filter> filters = new ArrayList<>();
    for (SecurityFilterChain chain : chains) {
      if (chain.matches(request)) {
        filters.addAll(chain.getFilters());
      }
    }
    return filters;
  }

}
