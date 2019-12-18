package nl._42.boot.saml.config;

import nl._42.boot.saml.SAMLProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Component
class SAMLLoginUrlResolver {

    private final RestTemplate template = new RestTemplate();
    private final SAMLProperties properties;

    SAMLLoginUrlResolver(SAMLProperties properties) {
        this.properties = properties;
    }

    public String getLoginUrl(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return "";
        }

        String successUrl = request.getParameter("successUrl");
        String loginUrl = getLoginUrl(successUrl);

        if (properties.isSkipLoginRedirect()) {
            loginUrl = getLocation(loginUrl);
        }

        return loginUrl;
    }

    private String getLoginUrl(String successUrl) {
        UriBuilder builder = new UriBuilder(properties.getSpBaseUrl()).path("/saml/login");
        if (isNotEmpty(successUrl)) {
            builder.append("?successUrl=").append(successUrl);
        }
        return builder.build();
    }

    private String getLocation(String url) {
        ResponseEntity<String> entity = template.getForEntity(url, String.class);
        return entity.getHeaders().getLocation().toString();
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
