package nl._42.boot.saml.user;

import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.springframework.security.saml.SAMLCredential;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@AllArgsConstructor
public class SAMLResponse {

    private final SAMLCredential credential;

    public SAMLAttribute getAttribute(String name) {
        Attribute attribute = get(name);
        return new SAMLAttribute(attribute);
    }

    private Attribute get(String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }

        return credential.getAttribute(name);
    }

    public Stream<SAMLAttribute> getAttributes() {
        return credential.getAttributes().stream().map(SAMLAttribute::new);
    }

    @AllArgsConstructor
    public static class SAMLAttribute {

        private final Attribute attribute;

        public String getName() {
            return attribute.getName();
        }

        public List<String> getValues() {
            return stream().collect(Collectors.toList());
        }

        public Optional<String> getValue() {
            return stream().findFirst();
        }

        public Stream<String> stream() {
            if (attribute == null) {
                return Stream.empty();
            }

            return attribute
              .getAttributeValues()
              .stream()
              .map(this::getValueAsString)
              .filter(StringUtils::isNotBlank);
        }

        private String getValueAsString(XMLObject object) {
            if (object instanceof XSStringImpl) {
                return ((XSStringImpl) object).getValue();
            } else if (object instanceof XSAnyImpl) {
                return ((XSAnyImpl) object).getTextContent();
            }
            return null;
        }

    }

}
