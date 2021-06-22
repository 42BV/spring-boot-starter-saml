package nl._42.boot.saml.springsecurity.web;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.common.binding.decoding.URIComparator;
import org.opensaml.util.URLBuilder;

import java.util.HashMap;
import java.util.Map;

public class FriendlyURLComparator implements URIComparator {

    private final Map<String, String> aliases = new HashMap<>();

    public FriendlyURLComparator(Map<String, String> aliases) {
        this.aliases.putAll(aliases);
    }

    @Override
    public boolean compare(String destination, String request) {
        if (StringUtils.equalsIgnoreCase(destination, request)) {
            return true;
        } else if (StringUtils.isBlank(request) || StringUtils.isBlank(destination)) {
            return false;
        } else {
            URLBuilder destinationUrl = new URLBuilder(destination);
            URLBuilder requestUrl = new URLBuilder(request);

            boolean equals = false;
            if (hasHost(destinationUrl, requestUrl)) {
                equals = hasContextPath(destinationUrl, requestUrl);
            }
            return equals;
        }
    }

    private boolean hasHost(URLBuilder destinationUrl, URLBuilder requestUrl) {
        return hasHost(destinationUrl.getHost(), requestUrl.getHost());
    }

    private boolean hasHost(String destinationHost, String requestHost) {
        boolean equals = StringUtils.equalsIgnoreCase(destinationHost, requestHost);
        if (!equals) {
            equals = StringUtils.equalsIgnoreCase(destinationHost, aliases.get(requestHost));
        }
        return equals;
    }

    private boolean hasContextPath(URLBuilder destinationUrl, URLBuilder requestUrl) {
        return StringUtils.equalsIgnoreCase(destinationUrl.getPath(), requestUrl.getPath());
    }

}
