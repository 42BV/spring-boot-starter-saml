package nl._42.boot.saml.user;

import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@AllArgsConstructor
public class RoleMapper {

    private final Map<String, String> roles;

    public Collection<GrantedAuthority> getAuthorities(Collection<String> roles) {
        return roles.stream()
                    .map(this::getRole)
                    .filter(StringUtils::isNotBlank)
                    .distinct()
                    .sorted()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
    }

    public String getRole(String value) {
        return roles.get(value);
    }

}
