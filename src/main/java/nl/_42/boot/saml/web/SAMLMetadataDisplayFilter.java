package nl._42.boot.saml.web;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.SAMLException;
import com.onelogin.saml2.settings.Saml2Settings;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;

public class SAMLMetadataDisplayFilter extends AbstractSAMLFilter {

    private static final String SPRING_SAML_METADATA = "spring_saml_metadata";

    private static final String XML = ".xml";
    private static final String SEPARATOR = "-";
    private static final String PROTOCOL = "://";
    private static final String PATH = "/";

    private final String fileName;

    public SAMLMetadataDisplayFilter(Saml2Settings settings, String provider) {
        super(settings);

        this.fileName = getMetadataFileName(provider);
    }

    static String getMetadataFileName(String provider) {
        String fileName = getName(provider);
        return StringUtils.defaultIfBlank(fileName, SPRING_SAML_METADATA) + XML;
    }

    private static String getName(String provider) {
        String name = StringUtils.substringAfter(provider, PROTOCOL);
        if (StringUtils.isNotBlank(name)) {
            name = StringUtils.substringBefore(name, PATH);
            name = name.replaceAll("\\.", SEPARATOR).replaceAll("/", SEPARATOR);
        }
        return name;
    }

    @Override
    protected void doFilter(Auth auth, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws SAMLException, IOException {
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + this.fileName + "\"");

        try {
            String metadata = auth.getSettings().getSPMetadata();
            response.getWriter().append(metadata);
        } catch (CertificateEncodingException e) {
            throw new SAMLException("Could not retrieve metadata", e);
        }
    }

}
