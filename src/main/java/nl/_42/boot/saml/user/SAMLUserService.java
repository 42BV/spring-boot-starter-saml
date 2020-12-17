package nl._42.boot.saml.user;

import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.SAMLProperties;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * SAML implementation of retrieving the user details. Reads the user identifier 
 * from the SAML credentials and then joins this with the person data stored in
 * our system.
 *
 * @author Jeroen van Schagen
 * @since Nov 18, 2014
 */
@Slf4j
public class SAMLUserService {

    private static final String USER_NAME = "user";
    private static final String ROLE_NAME = "role";

    private final Map<String, String> attributes;
    private final Assertions assertions;

    private final RoleMapper roleMapper;
    private final boolean roleRequired;

    private List<SAMLUserDecorator> decorators = new ArrayList<>();

    public SAMLUserService(SAMLProperties properties) {
        Objects.requireNonNull(properties, "Properties are required");

        this.attributes = properties.getAttributes();
        this.assertions = new Assertions(
            properties.getAssertions()
        );

        this.roleMapper = properties.getRoleMapper();
        this.roleRequired = properties.isRoleRequired();
    }

    public UserDetails load(SAMLResponse response) throws AuthenticationException {
        UserDetails user = build(response);
        return decorate(user, response);
    }

    private UserDetails build(SAMLResponse response) {
        log.debug("Loading user by SAML credentials...");

        String userName = getUserName(response);
        Collection<GrantedAuthority> authorities = getAuthorities(response);

        assertions.verify((name) -> {
            String attribute = attributes.getOrDefault(name, name);
            return response.getValues(attribute);
        });

        return new User(userName, "", authorities);
    }

    private String getUserName(SAMLResponse response) {
        String attribute = attributes.getOrDefault(USER_NAME, "");
        String userName = response.getValue(attribute).orElseGet(response::getName);

        if (StringUtils.isBlank(userName)) {
            throw new UserNotAllowedException(
                "Missing user name in SAML response, please provide a Name ID or user attribute"
            );
        }

        return userName;
    }

    private Collection<GrantedAuthority> getAuthorities(SAMLResponse response) {
        String attribute = attributes.getOrDefault(ROLE_NAME, ROLE_NAME);

        Set<String> roles = response.getValues(attribute);
        Collection<GrantedAuthority> authorities = roleMapper.getAuthorities(roles);

        if (isNotAllowed(authorities)) {
            String granted = roles.stream().collect(Collectors.joining(","));
            throw new UserNotAllowedException("User has no authorized roles, found: " + granted);
        }

        return authorities;
    }

    private boolean isNotAllowed(Collection<GrantedAuthority> authorities) {
        return roleRequired && authorities.isEmpty();
    }

    private UserDetails decorate(UserDetails details, SAMLResponse response) {
        for (SAMLUserDecorator decorator : decorators) {
            details = decorator.decorate(details, response);
        }
        return details;
    }

    @Autowired(required = false)
    public void setDecorators(List<SAMLUserDecorator> decorators) {
        this.decorators = decorators;
    }

}
