package nl._42.boot.saml.config;

import lombok.AllArgsConstructor;

import javax.servlet.http.HttpServletRequest;

import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@AllArgsConstructor
class UrlSAMLConfigResolver implements SAMLConfigResolver {

  private final String baseUrl;

  @Override
  public SAMLConfig getConfig(HttpServletRequest request) {
    String successUrl = request.getParameter("successUrl");

    String loginUrl = getLoginUrl(successUrl);
    return new SAMLConfig(loginUrl);
  }

  private String getLoginUrl(String successUrl) {
    UriBuilder builder = new UriBuilder(baseUrl).path("/saml/login");

    if (isNotEmpty(successUrl)) {
      builder.append("?successUrl=").append(successUrl);
    }

    return builder.build();
  }

  private class UriBuilder {

    private StringBuilder uri;

    UriBuilder(String host) {
      uri = new StringBuilder();
      append(host);
    }

    UriBuilder path(String path) {
      if (!path.isEmpty() && !path.startsWith("/")) {
        uri.append("/");
      }
      return append(path);
    }

    UriBuilder append(String value) {
      if (value.endsWith("/")) {
        String stripped = value.substring(0, value.length() - 1);
        return append(stripped);
      }

      uri.append(value);
      return this;
    }

    String build() {
      return uri.toString();
    }

  }

}
