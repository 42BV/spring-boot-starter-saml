package nl._42.boot.saml.config;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;

@RestController
@AllArgsConstructor
@RequestMapping("/saml/config")
public class SAMLConfigController {

    private final SAMLLoginUrlResolver resolver;

    @GetMapping
    public Map<String, String> getConfig(HttpServletRequest request) {
        String loginUrl = resolver.getLoginUrl(request);
        return Collections.singletonMap("loginUrl", loginUrl);
    }

}
