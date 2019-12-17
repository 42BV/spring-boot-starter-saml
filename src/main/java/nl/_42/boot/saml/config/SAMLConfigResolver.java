package nl._42.boot.saml.config;

import javax.servlet.http.HttpServletRequest;

interface SAMLConfigResolver {

  SAMLConfig getConfig(HttpServletRequest request);

}
