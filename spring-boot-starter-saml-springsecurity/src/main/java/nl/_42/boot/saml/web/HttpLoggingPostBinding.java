package nl._42.boot.saml.web;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPTransport;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.security.saml.processor.HTTPPostBinding;

@Slf4j
public class HttpLoggingPostBinding extends HTTPPostBinding {

    private static final String POST = "POST";

    private static final String REQUEST = "SAMLRequest";
    private static final String RESPONSE = "SAMLResponse";

    public HttpLoggingPostBinding(ParserPool parserPool, MessageDecoder decoder, MessageEncoder encoder) {
        super(parserPool, decoder, encoder);
    }

    public boolean supports(InTransport transport) {
        boolean supports = false;
        if (transport instanceof HTTPInTransport) {
            HTTPTransport http = (HTTPTransport) transport;
            String method = http.getHTTPMethod();
            supports = POST.equalsIgnoreCase(method) && hasParameters(http);
        }
        return supports;
    }

    private boolean hasParameters(HTTPTransport http) {
        if (hasParameter(http, REQUEST) || hasParameter(http, RESPONSE)) {
            return true;
        }

        log.info("Expected a SAMLRequest or SAMLResponse parameter, but received none.");
        return false;
    }

    private boolean hasParameter(HTTPTransport http, String name) {
        return http.getParameterValue(name) != null;
    }

}
