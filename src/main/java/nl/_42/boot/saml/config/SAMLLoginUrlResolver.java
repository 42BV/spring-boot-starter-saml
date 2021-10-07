package nl._42.boot.saml.config;

import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.SAMLProperties;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Objects;

import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Slf4j
@Component
class SAMLLoginUrlResolver {

    private final SAMLProperties properties;
    private final RestTemplate template;

    SAMLLoginUrlResolver(SAMLProperties properties) {
        this.properties = properties;

        this.template = new RestTemplate();
        template.setErrorHandler(new EmptyErrorHandler());
    }

    public String getLoginUrl(HttpServletRequest request) {
        if (!properties.isEnabled() && StringUtils.isBlank(properties.getSpLoginUrl())) {
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
        UrlBuilder builder = getLoginUrl();
        if (isNotEmpty(successUrl)) {
            builder.append("?successUrl=").append(successUrl);
        }
        return builder.build();
    }

    private UrlBuilder getLoginUrl() {
        if (StringUtils.isNotBlank(properties.getSpLoginUrl())) {
            return new UrlBuilder(properties.getSpLoginUrl());
        }

        return new UrlBuilder(properties.getSpBaseUrl()).path("/saml/login");
    }

    private String getLocation(String url) {
        ResponseEntity<String> entity = template.getForEntity(url, String.class);

        HttpStatus status = entity.getStatusCode();
        URI location = entity.getHeaders().getLocation();

        if (location != null) {
            url = location.toString();
        } else if (status.is3xxRedirection()) {
            Objects.requireNonNull("SAML login with status " + status.value() + " (redirect) is missing the required 'Location' header");
        } else if (status.isError()) {
            log.warn("Expected HTTP status 3xx (redirect) on login, but received error status {}", status.value());
        } else {
            log.warn("Expected HTTP status 3xx (redirect) on login, but received status {}, please disable 'saml.skip_login_redirect'", status.value());
        }

        return url;
    }

    private class UrlBuilder {

        private StringBuilder url;

        UrlBuilder(String baseUrl) {
            url = new StringBuilder();
            append(baseUrl);
        }

        UrlBuilder path(String path) {
            if (!path.isEmpty() && !path.startsWith("/")) {
                url.append("/");
            }
            return append(path);
        }

        UrlBuilder append(String value) {
            if (value.endsWith("/")) {
                String stripped = value.substring(0, value.length() - 1);
                return append(stripped);
            }

            url.append(value);
            return this;
        }

        String build() {
            return url.toString();
        }

    }

    private static class EmptyErrorHandler implements ResponseErrorHandler {

        @Override
        public boolean hasError(ClientHttpResponse response) {
            return false;
        }

        @Override
        public void handleError(ClientHttpResponse response) {
        }

    }

}
