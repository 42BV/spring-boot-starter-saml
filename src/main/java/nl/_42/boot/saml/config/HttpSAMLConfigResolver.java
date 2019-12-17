package nl._42.boot.saml.config;

import lombok.Setter;
import nl._42.boot.saml.SAMLProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

@Component
class HttpSAMLConfigResolver implements SAMLConfigResolver {

    private final UrlSAMLConfigResolver delegate;

    @Setter
    private RestTemplate template = new RestTemplate();

    @Autowired
    public HttpSAMLConfigResolver(SAMLProperties properties) {
        this(properties.getServiceProviderBaseUrl());
    }

    protected HttpSAMLConfigResolver(String baseUrl) {
        this.delegate = new UrlSAMLConfigResolver(baseUrl);
    }

    @Override
    public SAMLConfig getConfig(HttpServletRequest request) {
        String loginUrl = delegate.getConfig(request).getLoginUrl();
        String location = getLocation(loginUrl);

        return new SAMLConfig(location);
    }

    private String getLocation(String url) {
        ResponseEntity<String> entity = template.getForEntity(url, String.class);
        return entity.getHeaders().getLocation().toString();
    }

}
