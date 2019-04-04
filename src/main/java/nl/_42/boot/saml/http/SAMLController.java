package nl._42.boot.saml.http;

import nl._42.boot.saml.SAMLProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@Controller
@RequestMapping("/saml")
public class SAMLController {

    private final SAMLProperties properties;
    
    private final MetadataManager metadata;

    @Autowired
    public SAMLController(SAMLProperties properties, MetadataManager metadata) {
        this.properties = properties;
        this.metadata = metadata;
    }

    @GetMapping("/idpSelection")
    public String idpSelection(HttpServletRequest request, Model model, Principal principal) {
        if (isAuthenticated(principal)) {
            throw new IllegalArgumentException("User is already logged in.");
        } else if (!isForwarded(request)) {
            throw new IllegalArgumentException("Cannot directly access this service.");
        } else {
            model.addAttribute("idps", metadata.getIDPEntityNames());
            return "redirect:/saml/login?idp=" + properties.getIdpUrl();
        }
    }

    private static boolean isForwarded(HttpServletRequest request) {
        return request.getAttribute("javax.servlet.forward.request_uri") != null;
    }

    private static boolean isAuthenticated(Principal authentication) {
        return authentication != null && !(authentication instanceof AnonymousAuthenticationToken);
    }

}
