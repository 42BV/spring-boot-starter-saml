package nl._42.boot.saml.user;

import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.SAMLProperties;
import nl._42.boot.saml.UserNotAllowedException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * SAML implementation of retrieving the user details. Reads the user identifier 
 * from the SAML credentials and then joins this with the person data stored in
 * our system.
 *
 * @author Jeroen van Schagen
 * @since Nov 18, 2014
 */
@Slf4j
public class DefaultSAMLUserDetailsService implements SAMLUserDetailsService {

    private final SAMLProperties properties;
    private final SAMLUserMapper mapper;

    private final Values organisations;
    private final Values roles;

    public DefaultSAMLUserDetailsService(SAMLProperties properties, SAMLUserMapper mapper) {
        Objects.requireNonNull(properties, "Properties are required");
        this.properties = properties;

        if (mapper == null) {
            log.warn("No user mapper defined, please register a SAMLUserMapper bean.");
            mapper = new DefaultSAMLUserMapper();
        }

        this.mapper = mapper;

        this.organisations = Values.parse(properties.getAuthorizedOrganisations());
        this.roles = Values.parse(properties.getAuthorizedRoles());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public User loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        SAMLResponse response = new SAMLResponse(credential);
        return load(response);
    }

    private User load(SAMLResponse response) {
        log.debug("Loading user by SAML credentials...");
        response.getAttributes().forEach(attr ->
          log.trace("Attribute: {} = '{}'", attr.getName(), attr.stream().collect(Collectors.joining(", ")))
        );

        SAMLUser user = new SAMLUser(response, properties);
        verifyHasRole(user);
        verifyHasOrganisation(user);
        return mapper.load(user);
    }

    private void verifyHasRole(SAMLUser user) {
        if (!roles.containsAny(user.getRoles())) {
            log.error("Could not log in '{}', request roles: {} but user has only these roles: {}", user, roles, user.getRoles());
            throw new UserNotAllowedException("User does not have the requested roles.");
        }
    }

    private void verifyHasOrganisation(SAMLUser user) {
        if (!organisations.containsAny(user.getOrganisations())) {
            log.error("Could not log in '{}', request organisations: {} but user has is only assigned to: {}", user, organisations, user.getOrganisations());
            throw new UserNotAllowedException("User is not assigned to one of the required organisations.");
        }
    }

    private static final class Values {

        private final Set<String> values;

        Values(String... values) {
            this.values = Stream.of(values)
              .filter(StringUtils::isNotBlank)
              .map(String::trim)
              .map(String::toLowerCase)
              .collect(Collectors.toSet());
        }

        static final Values parse(String text) {
            if (StringUtils.isNotBlank(text)) {
                return new Values(text.split("[ ]*,[ ]*"));
            } else {
                return new Values();
            }
        }

        boolean containsAny(Collection<String> expected) {
            if (values.isEmpty()) {
                return true;
            }

            return expected.stream().anyMatch(
              this::contains
            );
        }

        private boolean contains(String expected) {
            return values.contains(
              StringUtils.lowerCase(expected)
            );
        }

        @Override
        public String toString() {
            return values.toString();
        }

    }

}
