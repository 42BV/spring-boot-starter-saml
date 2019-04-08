package nl._42.boot.saml.user;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.springframework.security.saml.SAMLCredential;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
public class DefaultSAMLResponse implements SAMLResponse {

    @Getter
    private final SAMLCredential credential;

    @Override
    public Set<String> getValues(String name) {
        Attribute attribute = getAttribute(name);
        if (attribute == null) {
            return Collections.emptySet();
        }

        return attribute.getAttributeValues().stream()
                        .map(this::getValueAsString)
                        .collect(Collectors.toSet());
    }

    private Attribute getAttribute(String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }

        return credential.getAttribute(name);
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
