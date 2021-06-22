/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml.springsecurity.web;

import lombok.Setter;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.net.URLCodec;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * SAML entry point that redirects when matching a specific request, otherwise returns forbidden.
 *
 * @author Jeroen van Schagen
 * @since Oct 30, 2014
 */
public class SAMLDefaultEntryPoint extends SAMLEntryPoint {

    public static final String SUCCESS_URL_SESSION_KEY = "SuccessUrl";
    public static final String SUCCESS_URL_PARAMETER = "successUrl";

    private final RequestMatcher matcher;
    
    public SAMLDefaultEntryPoint(RequestMatcher matcher) {
        this.matcher = matcher;
    }

    @Setter
    private String parameterName = SUCCESS_URL_PARAMETER;

    @Setter
    private String baseUrl = "";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        configureSession(request);
        super.commence(request, response, exception);
    }

    private void configureSession(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String successUrl = getSuccessUrl(request);
        session.setAttribute(SUCCESS_URL_SESSION_KEY, successUrl);
    }

    private String getSuccessUrl(HttpServletRequest request) {
        String successUrl = request.getParameter(parameterName);
        if (StringUtils.isNotBlank(successUrl)) {
            return baseUrl + decode(successUrl);
        } else {
            return null;
        }
    }
    
    private static String decode(String url) {
        try {
            String result = new URLCodec().decode(url);
            return new URLCodec().decode(result);
        } catch (DecoderException e) {
            return null;
        }
    }

    @Override
    protected void initializeDiscovery(SAMLMessageContext context) throws ServletException, IOException, MetadataProviderException {
        HttpServletRequest request = ((HttpServletRequestAdapter) context.getInboundMessageTransport()).getWrappedRequest();
        HttpServletResponse response = ((HttpServletResponseAdapter) context.getOutboundMessageTransport()).getWrappedResponse();
        if (matcher.matches(request)) {
            super.initializeDiscovery(context);
        } else {
            response.setStatus(HttpStatus.FORBIDDEN.value());
        }
    }
    
}
