package nl._42.boot.saml.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
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

  private final MetadataGeneratorFilter generator;

  private final List<SecurityFilterChain> filters = new ArrayList<>();

  public SAMLFilter(MetadataGeneratorFilter generator) {
    this.generator = generator;
  }

  public void on(String url, Filter filter) {
    AntPathRequestMatcher matcher = new AntPathRequestMatcher(url);
    filters.add(new DefaultSecurityFilterChain(matcher, filter));
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    Filter filter = getFilter(httpServletRequest);

    if (filter == null) {
      chain.doFilter(request, response);
    } else {
      proceed(request, response, filter, chain);
    }
  }

  private void proceed(ServletRequest request, ServletResponse response, Filter filter, FilterChain chain) throws IOException, ServletException {
    // Ensure metadata generation is performed
    generator.doFilter(request, response, (req, res) -> {});

    // Perform SAML action
    filter.doFilter(request, response, chain);
  }

  private Filter getFilter(HttpServletRequest request) {
    return filters.stream()
                  .filter(filter -> filter.matches(request))
                  .flatMap(chain -> chain.getFilters().stream())
                  .findFirst().orElse(null);
  }

}
