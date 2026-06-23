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
package it.infn.mw.iam.authn.util;

import static java.util.Collections.emptyMap;

import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.google.common.collect.Maps;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

public class JwtUtils {
  public static final Logger LOG = LoggerFactory.getLogger(JwtUtils.class);

  private JwtUtils() {
    // empty on purpose
  }

  public static Map<String, String> getClaimsAsMap(JWT jwt) {

    Map<String, String> claimsMap = Maps.newHashMap();

    JWTClaimsSet claims;

    try {
      claims = jwt.getJWTClaimsSet();
    } catch (ParseException e) {
      LOG.warn("Error parsing jwt claims: {}", e.getMessage(), e);
      return emptyMap();
    }

    for (String claimName : claims.getClaims().keySet()) {
      Object claimValue = claims.getClaim(claimName);

      if (claimValue instanceof String) {
        claimsMap.put(claimName, (String) claimValue);
      } else if (claimValue instanceof Number) {
        claimsMap.put(claimName, String.valueOf(claimValue));
      } else if (claimValue instanceof URI) {
        claimsMap.put(claimName, ((URI) claimValue).toString());
      } else if (claimValue instanceof URL) {
        claimsMap.put(claimName, ((URL) claimValue).toString());
      } else {
        LOG.warn("Unsupported claim type '{}' for claim '{}'... skipping it",
            claimValue.getClass().getName(), claimName);
      }
    }
    return claimsMap;
  }

  public static JWTClaimsSet parseClaims(JWT idToken) {

    try {
      return idToken.getJWTClaimsSet();
    } catch (ParseException e) {
      throw new AuthenticationServiceException("Error parsing JWT claims: " + e.getMessage());
    }

  }

  public static JWT parseToken(String tokenValue) {

    try {
      return JWTParser.parse(tokenValue);

    } catch (ParseException e) {
      throw new AuthenticationServiceException("Token parse error");
    }
  }

  public static JsonObject jsonStringSanityChecks(String jsonString) {

    JsonElement jsonRoot = JsonParser.parseString(jsonString);
    if (!jsonRoot.isJsonObject()) {
      throw new AuthenticationServiceException("Not a JSON object: " + jsonRoot);
    }

    return jsonRoot.getAsJsonObject();
  }

}
