package nl._42.boot.saml.onelogin.user;

import com.onelogin.saml2.Auth;
import lombok.AllArgsConstructor;
import nl._42.boot.saml.user.SAMLResponse;
import org.apache.commons.lang3.StringUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@AllArgsConstructor
class SAMLResponseImpl implements SAMLResponse {

    private final Auth auth;

    @Override
    public String getName() {
        return auth.getNameId();
    }

    @Override
    public Collection<String> getAttributes() {
        List<String> names = auth.getAttributesName();
        return Collections.unmodifiableList(names);
    }

    @Override
    public Set<String> getValues(String name) {
        if (StringUtils.isBlank(name)) {
            return Collections.emptySet();
        }

        Collection<String> attribute = auth.getAttribute(name);
        if (attribute == null) {
            return Collections.emptySet();
        }

        return new HashSet<>(attribute);
    }

}
