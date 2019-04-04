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

    public Value get(String key) {
        Attribute attribute = credential.getAttribute(key);
        return new Value(attribute);
    }

    public Stream<Value> stream() {
        return credential.getAttributes().stream().map(Value::new);
    }

    @AllArgsConstructor
    public static class Value {

        private final Attribute attribute;

        public String getName() {
            return attribute.getName();
        }

        public List<String> values() {
            return stream().collect(Collectors.toList());
        }

        public Optional<String> value() {
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
