package nl._42.boot.saml.config;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@AllArgsConstructor
@RequestMapping("/saml/config")
public class SAMLConfigController {

    private final SAMLConfigResolver resolver;

    @GetMapping
    public SAMLConfig getConfig(HttpServletRequest request) {
        return resolver.getConfig(request);
    }

}
