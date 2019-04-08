package nl._42.boot.saml.user;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MapSAMLResponse implements SAMLResponse {

    private final Map<String, Set<String>> attributes = new HashMap<>();

    public void put(String name, String... values) {
        List<String> collection = Arrays.asList(values);
        attributes.put(name, new HashSet<>(collection));
    }

    @Override
    public Set<String> getValues(String name) {
        return attributes.getOrDefault(name, Collections.emptySet());
    }

}
