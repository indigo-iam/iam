package it.infn.mw.iam.core.oauth.scope;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;

import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class IamOpaScopeFilter {
  
  @Autowired
  private IamOpaController opaService;
  
  public Set<String> opaScopeFilter(IamAccount account, Set<String> scopes) {
    JSONObject input = new JSONObject();
    Set<String> filteredScopes = new HashSet<>();

    input.put("id",  account.getUuid());
    input.put("type", "account");
    input.put("scopes", scopes);

    try {
      JSONObject result =
          new ObjectMapper().readValue(opaService.evaluatePolicy(input), JSONObject.class);
      String substringBetween =
          StringUtils.substringBetween(result.getAsString("filtered_scopes"), "[", "]")
            .replaceAll("\"", ""); // get rid of bracket
      filteredScopes = new HashSet<String>(Arrays.asList(substringBetween.split(", ")));

    } catch (JsonProcessingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return filteredScopes;
  }

}
