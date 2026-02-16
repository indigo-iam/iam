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
package it.infn.mw.iam.persistence.model.serializer;

import java.lang.reflect.Type;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import it.infn.mw.iam.persistence.model.ApprovedSite;

public class ApprovedSiteSerializer implements JsonSerializer<ApprovedSite> {

  @Override
  public JsonElement serialize(ApprovedSite src, Type typeOfSrc, JsonSerializationContext context) {

    JsonObject json = new JsonObject();

    json.addProperty("id", src.getId());
    json.addProperty("creationDate", src.getCreationDate().toString());
    if (src.getAccessDate() != null) {
      json.addProperty("accessDate", src.getAccessDate().toString());
    } else {
      json.add("accessDate", JsonNull.INSTANCE);
    }
    if (src.getTimeoutDate() != null) {
      json.addProperty("timeoutDate", src.getTimeoutDate().toString());
    } else {
      json.add("timeoutDate", JsonNull.INSTANCE);
    }
    json.addProperty("clientId", src.getClient().getClientId());
    json.addProperty("userId", src.getAccount().getUsername());

    JsonArray scopes = new JsonArray();
    src.getAllowedScopes().forEach(scopes::add);
    json.add("scope", scopes);

    return json;
  }

}
