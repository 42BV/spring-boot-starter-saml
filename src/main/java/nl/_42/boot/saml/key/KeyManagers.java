package nl._42.boot.saml.key;

import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;

import java.util.Collections;
import java.util.Map;

public final class KeyManagers {

  private static final KeyManager EMPTY = new EmptyKeyManager();

  private KeyManagers() {
  }

  public static KeyManager build(KeystoreProperties properties) {
    String fileName = properties.getFileName();

    if (StringUtils.isBlank(fileName)) {
      return EMPTY;
    } else {
      return buildJks(properties);
    }
  }

  private static KeyManager buildJks(KeystoreProperties properties) {
    Resource storeFile = new DefaultResourceLoader().getResource(properties.getFileName());
    Map<String, String> passwords = Collections.singletonMap(properties.getUser(), properties.getPassword());
    return new JKSKeyManager(storeFile, properties.getPassword(), passwords, properties.getKey());
  }

}
