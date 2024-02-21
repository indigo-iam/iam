/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

    input.put("id", account.getUuid());
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
