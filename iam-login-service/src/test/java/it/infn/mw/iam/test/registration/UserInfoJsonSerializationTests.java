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
package it.infn.mw.iam.test.registration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

class UserInfoJsonSerializationTests {

  private final Gson gson = new GsonBuilder().create();

  @Test
  void shouldEncodeSpecialCharactersInJson() {
    String maliciousValue = "<script>alert('Hello')</script>";

    JsonObject userInfo = new JsonObject();
    userInfo.addProperty("family_name", maliciousValue);
    userInfo.addProperty("given_name", maliciousValue);

    String json = gson.toJson(userInfo);

    // JSON should not contain literal HTML tag
    assertFalse(json.contains("<"));
    assertFalse(json.contains(">"));
    assertFalse(json.contains("</script>"));

    // Original data must be retrieved
    JsonObject parsedJson = JsonParser.parseString(json).getAsJsonObject();

    assertEquals(maliciousValue, parsedJson.get("family_name").getAsString());
    assertEquals(maliciousValue, parsedJson.get("given_name").getAsString());
  }

  @Test
  void shouldPreserveAmpersandDuringSerialization() {
    String originalValue = "Rossi & Bianchi";

    JsonObject userInfo = new JsonObject();
    userInfo.addProperty("family_name", originalValue);

    String json = gson.toJson(userInfo);

    assertTrue(json.contains("\\u0026"));

    JsonObject parsedJson = JsonParser.parseString(json).getAsJsonObject();

    assertEquals(originalValue, parsedJson.get("family_name").getAsString());
  }
}
