package nl._42.boot.saml.user;

import lombok.Getter;
import nl._42.boot.saml.SAMLProperties;
import org.apache.commons.lang3.StringUtils;

import java.util.List;

import static java.lang.String.format;

@Getter
public class SAMLUser {

    private final SAMLResponse response;

    private final String userId;
    private final String displayName;
    private final List<String> roles;
    private final List<String> organisations;

    public SAMLUser(SAMLResponse response, SAMLProperties properties) {
        this.response = response;

        userId = response.get(properties.getUserIdName()).value().orElse("");
        if (StringUtils.isBlank(userId)) {
            throw new IllegalStateException(format("User identifier is required, missing attribute '%s'", properties.getUserIdName()));
        }

        displayName = response.get(properties.getDisplayName()).value().orElse(userId);
        roles = response.get(properties.getRoleName()).values();
        organisations = response.get(properties.getOrganisationName()).values();
    }

}
