package it.infn.mw.iam.authn;

import java.util.Collections;
import java.util.Map;

import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

@Component
public class DefaultExternalAuthenticationInfoProcessor
    implements ExternalAuthenticationInfoProcessor {

  public DefaultExternalAuthenticationInfoProcessor() {}

  @Override
  public Map<String, String> process(OAuth2Authentication authentication) {

    SavedUserAuthentication userAuth =
        (SavedUserAuthentication) authentication.getUserAuthentication();

    if (userAuth == null || userAuth.getAdditionalInfo().isEmpty()) {
      return Collections.emptyMap();
    }

    return userAuth.getAdditionalInfo();
  }

}
