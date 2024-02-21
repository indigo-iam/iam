package it.infn.mw.iam.core.oauth.scope;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;

import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@Component
public class IamOpaFilter {
  
  @Autowired
  private IamOpaController opaService;
  
  public void filterScopesWithOPA(OAuth2Authentication authentication, Optional<IamAccount> maybeAccount, OAuth2AccessToken accessToken) {
    
    OAuth2Request originalAuthRequest = authentication.getOAuth2Request();
    
    JSONObject input = new JSONObject();
    Set<String> filteredScopes = new HashSet<>();

    if (maybeAccount.isPresent()) {
      input.put("id",  maybeAccount.get().getUuid());
      input.put("type", "account");
      input.put("scopes", originalAuthRequest.getScope());
    }
    else {
      input.put("id",  originalAuthRequest.getClientId());
      input.put("type", "client");
      input.put("scopes", originalAuthRequest.getScope());
    }

    try {
      JSONObject result =
          new ObjectMapper().readValue(opaService.evaluatePolicy(input), JSONObject.class);
      String substringBetween =
          StringUtils.substringBetween(result.getAsString("filtered_scopes"), "[", "]")
            .replaceAll("\"", ""); // get rid of bracket
      filteredScopes = new HashSet<String>(Arrays.asList(substringBetween.split(", ")));
      accessToken.getScope().retainAll(filteredScopes);

    } catch (JsonProcessingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    
  }

}
