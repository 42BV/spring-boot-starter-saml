package nl._42.boot.saml.user;

import java.util.Optional;
import java.util.Set;

public interface SAMLResponse {

    default Optional<String> getValue(String name) {
        return getValues(name).stream().sorted().findFirst();
    }

    Set<String> getValues(String name);

}
