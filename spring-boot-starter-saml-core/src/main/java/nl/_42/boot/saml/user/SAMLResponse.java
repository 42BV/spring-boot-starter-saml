package nl._42.boot.saml.user;

import org.apache.commons.lang3.StringUtils;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;

public interface SAMLResponse {

    String getName();

    Collection<String> getAttributes();

    Set<String> getValues(String attribute);

    default Optional<String> getValue(String attribute) {
        return getValues(attribute)
            .stream()
            .sorted()
            .filter(StringUtils::isNotBlank)
            .findFirst();
    }

}
