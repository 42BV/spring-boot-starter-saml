package nl._42.boot.saml;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class SAMLEnabledCondition implements Condition {
    
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        return context.getEnvironment().getProperty("saml.enabled", boolean.class, true) == true;
    }
    
}
