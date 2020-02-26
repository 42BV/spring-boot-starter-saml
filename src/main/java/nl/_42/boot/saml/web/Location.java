package nl._42.boot.saml.web;

import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class Location {

    private static final String HEADER = "Location";

    static void redirectTo(HttpServletRequest request, HttpServletResponse response, String url) {
        String location = getLocation(request, url);
        response.setHeader(HEADER, location);
        response.setStatus(HttpStatus.SEE_OTHER.value());
    }

    private static String getLocation(HttpServletRequest request, String url) {
        if (StringUtils.startsWith(url, "/")) {
            return request.getRemoteHost() + url;
        }

        return url;
    }

}
