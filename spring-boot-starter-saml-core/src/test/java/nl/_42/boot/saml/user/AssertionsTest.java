package nl._42.boot.saml.user;

import nl._42.boot.saml.UserNotAllowedException;
import nl._42.boot.saml.user.Assertions;
import org.junit.Test;

import java.util.Collections;

public class AssertionsTest {

    private final Assertions assertions = new Assertions(
        Collections.singletonMap("organisation", "surfguest.nl|harvard-example.edu|vorsen.nl")
    );

    @Test
    public void verify_shouldSucceed_whenOneOf() {
        assertions.verify((name) -> Collections.singleton("vorsen.nl"));
    }

    @Test(expected = UserNotAllowedException.class)
    public void verify_shouldThrow_whenInvalid() {
        assertions.verify((name) -> Collections.singleton("jaja.nl"));
    }

    @Test
    public void verify_shouldSucceed_whenEmpty() {
        Assertions assertions = new Assertions(
            Collections.emptyMap()
        );

        assertions.verify((name) -> Collections.singleton("vorsen.nl"));
        assertions.verify((name) -> Collections.singleton("jaja.nl"));
    }

}
