package nl._42.boot.saml.user;

import lombok.extern.slf4j.Slf4j;
import nl._42.boot.saml.SAMLProperties;
import nl._42.boot.saml.UserNotAllowedException;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml2.core.NameID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;

/**
 * SAML implementation of retrieving the user details. Reads the user identifier 
 * from the SAML credentials and then joins this with the person data stored in
 * our system.
 *
 * @author Jeroen van Schagen
 * @since Nov 18, 2014
 */
@Slf4j
public class SAMLUserService implements SAMLUserDetailsService {

    private static final String USER_NAME = "user";
    private static final String ROLE_NAME = "role";

    private final String userAttribute;
    private final String roleAttribute;

    private final RoleMapper roleMapper;
    private final boolean roleRequired;

    private List<SAMLUserDecorator> decorators = new ArrayList<>();

    public SAMLUserService(SAMLProperties properties) {
        Objects.requireNonNull(properties, "Properties are required");

        this.userAttribute = properties.getAttributes().getProperty(USER_NAME, "");
        this.roleAttribute = properties.getAttributes().getProperty(ROLE_NAME, ROLE_NAME);

        this.roleMapper = properties.getRoleMapper();
        this.roleRequired = properties.isRoleRequired();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UserDetails loadUserBySAML(SAMLCredential credential) {
        SAMLResponse response = new DefaultSAMLResponse(credential);

        UserDetails user = buildUser(credential, response);
        return decorate(user, response);
    }

    private UserDetails buildUser(SAMLCredential credential, SAMLResponse response) {
        log.debug("Loading user by SAML credentials...");

        String userName = getUserName(credential, response);
        Collection<GrantedAuthority> authorities = getAuthorities(response);
        return new User(userName, "", authorities);
    }

    private String getUserName(SAMLCredential credential, SAMLResponse response) {
        String userName = response.getValue(userAttribute).orElse("");
        if (StringUtils.isBlank(userName)) {
            userName = Optional.ofNullable(credential.getNameID()).map(NameID::getValue).orElse("");
        }

        if (StringUtils.isBlank(userName)) {
            throw new UserNotAllowedException(
                "Missing user name in SAML response, please provide a Name ID or user attribute"
            );
        }

        return userName;
    }

    private Collection<GrantedAuthority> getAuthorities(SAMLResponse response) {
        Collection<String> roles = response.getValues(roleAttribute);
        Collection<GrantedAuthority> authorities = roleMapper.getAuthorities(roles);

        if (isAllowed(authorities)) {
            String granted = roles.stream().collect(Collectors.joining(","));
            throw new UserNotAllowedException("User has no authorized roles, found: " + granted);
        }

        return authorities;
    }

    private boolean isAllowed(Collection<GrantedAuthority> authorities) {
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
