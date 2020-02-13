package nl._42.boot.saml.web;

import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SAMLMetadataDisplayFilter extends MetadataDisplayFilter {

  private static final String SPRING_SAML_METADATA = "spring_saml_metadata";

  private static final String XML = ".xml";
  private static final String SEPARATOR = "-";
  private static final String PROTOCOL = "://";
  private static final String PATH = "/";

  private final String fileName;

  public SAMLMetadataDisplayFilter(String provider) {
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
  protected void processMetadataDisplay(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    super.processMetadataDisplay(request, response);
    response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + this.fileName + "\"");
  }

}
