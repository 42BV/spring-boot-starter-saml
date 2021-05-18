/*
 * (C) 2014 42 bv (www.42.nl). All rights reserved.
 */
package nl._42.boot.saml;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Thrown whenever a user is not allowed.
 *
 * @author Jeroen van Schagen
 * @since Apr 28, 2015
 */
public class UserNotAllowedException extends UsernameNotFoundException {
    
    public UserNotAllowedException(String message) {
        super(message);
    }
    
}
