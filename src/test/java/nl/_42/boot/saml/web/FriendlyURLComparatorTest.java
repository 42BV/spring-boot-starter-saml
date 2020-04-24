package nl._42.boot.saml.web;

import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class FriendlyURLComparatorTest {

    private final FriendlyURLComparator comparator = new FriendlyURLComparator(
        Collections.singletonMap("localhost", "vu-uas-test.42.nl")
    );

    @Test
    public void compare_equal_shouldSucceed() {
        String receiverEndpoint = "https://vu-uas-test.42.nl:443/api/saml/SSO";
        String messageDestination = "https://vu-uas-test.42.nl:443/api/saml/SSO";

        assertTrue(comparator.compare(receiverEndpoint, messageDestination));
    }

    @Test
    public void compare_equalIgnoreCase_shouldSucceed() {
        String receiverEndpoint = "https://vu-uas-test.42.nl:443/api/saml/SSO";
        String messageDestination = "https://vu-uas-test.42.nl:443/api/saml/sso";

        assertTrue(comparator.compare(receiverEndpoint, messageDestination));
    }

    @Test
    public void compare_missingPort_shouldSucceed() {
        String receiverEndpoint = "https://vu-uas-test.42.nl:443/api/saml/SSO";
        String messageDestination = "https://vu-uas-test.42.nl/api/saml/SSO";

        assertTrue(comparator.compare(receiverEndpoint, messageDestination));
    }

    @Test
    public void compare_tlsTermination_shouldSucceed() {
        String receiverEndpoint = "http://vu-uas-test.42.nl/api/saml/SSO";
        String messageDestination = "https://vu-uas-test.42.nl:443/api/saml/SSO";

        assertTrue(comparator.compare(receiverEndpoint, messageDestination));
    }

    @Test
    public void compare_localhost_shouldSucceed() {
        String receiverEndpoint = "http://vu-uas-test.42.nl/api/saml/SSO";
        String messageDestination = "http://localhost:8080/api/saml/SSO";

        assertTrue(comparator.compare(receiverEndpoint, messageDestination));
    }

    @Test
    public void compare_localhost_missingPort_shouldSucceed() {
        String receiverEndpoint = "http://vu-uas-test.42.nl/api/saml/SSO";
        String messageDestination = "http://localhost/api/saml/SSO";

        assertTrue(comparator.compare(receiverEndpoint, messageDestination));
    }

    @Test
    public void compare_null_shouldSucceed() {
        assertTrue(comparator.compare(null, null));
    }

    @Test
    public void compare_receiverNull_shouldFail() {
        String messageDestination = "https://vu-uas-test.42.nl:443/api/saml/SSO";

        assertFalse(comparator.compare(null, messageDestination));
    }

    @Test
    public void compare_requestNull_shouldFail() {
        String receiverEndpoint = "https://vu-uas-test.42.nl:443/api/saml/SSO";

        assertFalse(comparator.compare(receiverEndpoint, " "));
    }

}
