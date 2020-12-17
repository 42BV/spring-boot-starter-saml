package nl._42.boot.saml.user;

import lombok.AllArgsConstructor;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static java.util.stream.Collectors.joining;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

@AllArgsConstructor
class Assertions {

    private final Map<String, String> assertions;

    void verify(Function<String, Set<String>> response) {
        assertions.keySet().forEach(name ->
            verify(name, response)
        );
    }

    private void verify(String name, Function<String, Set<String>> response) {
        String regex = assertions.get(name);

        if (isNotBlank(regex)) {
            Set<String> values = response.apply(name);
            if (values == null) {
                values = Collections.emptySet();
            }

            if (values.stream().noneMatch(value -> value.matches(regex))) {
                throw new UserNotAllowedException(
                    String.format(
                        "Assertion failure expected attribute %s to match %s, but was: %s",
                        name,
                        regex,
                        values.stream().collect(joining(", "))
                    )
                );
            }
        }
    }

}
