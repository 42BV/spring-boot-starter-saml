package nl._42.boot.saml.user;

import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

@AllArgsConstructor
public class RoleMapper {

    private final String prefix;
    private final Properties roles;

    public List<SimpleGrantedAuthority> getAuthorities(Collection<String> roles) {
        return roles.stream()
                    .map(this::getRole)
                    .filter(StringUtils::isNotBlank)
                    .distinct()
                    .sorted()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
    }

    public String getRole(String value) {
        String name = roles.getProperty(value);
        if (StringUtils.isNotBlank(name)) {
            name = prefix + name;
        }
        return name;
    }

}
