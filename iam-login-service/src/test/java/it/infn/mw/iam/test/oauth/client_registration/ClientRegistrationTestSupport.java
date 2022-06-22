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
package it.infn.mw.iam.test.oauth.client_registration;

import static com.google.common.collect.Sets.newHashSet;
import static org.mitre.oauth2.model.RegisteredClientFields.CLAIMS_REDIRECT_URIS;
import static org.mitre.oauth2.model.RegisteredClientFields.CLIENT_NAME;
import static org.mitre.oauth2.model.RegisteredClientFields.CONTACTS;
import static org.mitre.oauth2.model.RegisteredClientFields.GRANT_TYPES;
import static org.mitre.oauth2.model.RegisteredClientFields.REDIRECT_URIS;
import static org.mitre.oauth2.model.RegisteredClientFields.REQUEST_URIS;
import static org.mitre.oauth2.model.RegisteredClientFields.RESPONSE_TYPES;
import static org.mitre.oauth2.model.RegisteredClientFields.SCOPE;
import static org.mitre.util.JsonUtils.getAsArray;

import java.util.Set;

import org.mitre.oauth2.model.RegisteredClientFields;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import com.google.gson.JsonObject;

import it.infn.mw.iam.api.client.registration.ClientRegistrationApiController;

public class ClientRegistrationTestSupport {

  public static final String REGISTER_ENDPOINT = ClientRegistrationApiController.ENDPOINT;
  public static final String LEGACY_REGISTER_ENDPOINT =
      ClientRegistrationApiController.LEGACY_ENDPOINT;

  public static class ClientJsonStringBuilder {
    
    static final Joiner JOINER = Joiner.on(RegisteredClientFields.SCOPE_SEPARATOR);
    
    String name = "test_client";
    Set<String> redirectUris = Sets.newHashSet("http://localhost:9090");
    Set<String> grantTypes = Sets.newHashSet("client_credentials");
    Set<String> scopes = Sets.newHashSet();
    Set<String> responseTypes = Sets.newHashSet();
    
    private ClientJsonStringBuilder() {
    }
    
    public static ClientJsonStringBuilder builder() {
      return new ClientJsonStringBuilder();
    }
    
    public ClientJsonStringBuilder name(String name) {
      this.name = name;
      return this;
    }
    
    public ClientJsonStringBuilder redirectUris(String...uris) {
      this.redirectUris = Sets.newHashSet(uris);
      return this;
    }
    
    public ClientJsonStringBuilder grantTypes(String...grantTypes) {
      this.grantTypes = Sets.newHashSet(grantTypes);
      return this;
    }
    
    public ClientJsonStringBuilder scopes(String...scopes) {
      this.scopes = Sets.newHashSet(scopes);
      return this;
    }
    
    public ClientJsonStringBuilder responseTypes(String...responseTypes) {
      this.responseTypes = Sets.newHashSet(responseTypes);
      return this;
    }
    
    public String build() {
      JsonObject json = new JsonObject();
      json.addProperty(CLIENT_NAME, name);
      json.addProperty(SCOPE, JOINER.join(scopes));
      json.add(REDIRECT_URIS, getAsArray(redirectUris));
      json.add(GRANT_TYPES, getAsArray(grantTypes));
      json.add(RESPONSE_TYPES, getAsArray(responseTypes, true));
      json.add(CLAIMS_REDIRECT_URIS, getAsArray(newHashSet(), true));
      json.add(REQUEST_URIS, getAsArray(newHashSet(), true));
      json.add(CONTACTS, getAsArray(newHashSet("test@iam.test")));
     
      return json.toString();
    }
    
    
    
  }

  protected String setToString(Set<String> scopes) {
    Joiner joiner = Joiner.on(RegisteredClientFields.SCOPE_SEPARATOR);
    return joiner.join(scopes);
  }

}
