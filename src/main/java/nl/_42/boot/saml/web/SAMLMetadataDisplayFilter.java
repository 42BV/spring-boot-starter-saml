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
    private final String url;

    public SAMLMetadataDisplayFilter(Saml2Settings settings, String provider, String url) {
        super(settings);

        this.fileName = getMetadataFileName(provider);
        this.url = url;
    }

    static String getMetadataFileName(String provider) {
        String name = getName(provider);
        return name + XML;
    }

    private static String getName(String provider) {
        if (StringUtils.isBlank(provider)) {
            return SPRING_SAML_METADATA;
        }

        String name = provider;
        if (name.contains(PROTOCOL)) {
            name = StringUtils.substringAfter(provider, PROTOCOL);
        }
        if (name.contains(PATH)) {
            name = StringUtils.substringBefore(name, PATH);
        }
        return name.replaceAll("\\.", SEPARATOR).replaceAll("/", SEPARATOR);
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
