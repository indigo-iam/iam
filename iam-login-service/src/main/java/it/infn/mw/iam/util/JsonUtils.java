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
package it.infn.mw.iam.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

public class JsonUtils {

  private static final Logger logger = LoggerFactory.getLogger(JsonUtils.class);

  private static Gson gson = new Gson();

  public static JsonElement getAsArray(Set<String> value) {
    return getAsArray(value, false);
  }

  public static JsonElement getAsArray(Set<String> value, boolean preserveEmpty) {
    if (!preserveEmpty && value != null && value.isEmpty()) {
      return JsonNull.INSTANCE;
    }
    return gson.toJsonTree(value, new TypeToken<Set<String>>() {}.getType());
  }

  public static Date getAsDate(JsonObject o, String member) {
    if (o.has(member)) {
      JsonElement e = o.get(member);
      if (e != null && e.isJsonPrimitive()) {
        return new Date(e.getAsInt() * 1000L);
      }
    }
    return null;
  }

  public static JWEAlgorithm getAsJweAlgorithm(JsonObject o, String member) {
    String s = getAsString(o, member);
    if (s != null) {
      return JWEAlgorithm.parse(s);
    }
    return null;
  }

  public static EncryptionMethod getAsJweEncryptionMethod(JsonObject o, String member) {
    String s = getAsString(o, member);
    if (s != null) {
      return EncryptionMethod.parse(s);
    }
    return null;
  }

  public static JWSAlgorithm getAsJwsAlgorithm(JsonObject o, String member) {
    String s = getAsString(o, member);
    if (s != null) {
      return JWSAlgorithm.parse(s);
    }
    return null;
  }

  public static PKCEAlgorithm getAsPkceAlgorithm(JsonObject o, String member) {
    String s = getAsString(o, member);
    if (s != null) {
      return PKCEAlgorithm.parse(s);
    }
    return null;
  }

  public static String getAsString(JsonObject o, String member) {
    if (o.has(member)) {
      JsonElement e = o.get(member);
      if (e != null && e.isJsonPrimitive()) {
        return e.getAsString();
      }
    }
    return null;
  }

  public static Boolean getAsBoolean(JsonObject o, String member) {
    if (o.has(member)) {
      JsonElement e = o.get(member);
      if (e != null && e.isJsonPrimitive()) {
        return e.getAsBoolean();
      }
    }
    return null;
  }

  public static Long getAsLong(JsonObject o, String member) {
    if (o.has(member)) {
      JsonElement e = o.get(member);
      if (e != null && e.isJsonPrimitive()) {
        return e.getAsLong();
      }
    }
    return null;
  }

  public static Set<String> getAsStringSet(JsonObject o, String member) throws JsonSyntaxException {
    if (o.has(member)) {
      if (o.get(member).isJsonArray()) {
        return gson.fromJson(o.get(member), new TypeToken<Set<String>>() {}.getType());
      }
      return Sets.newHashSet(o.get(member).getAsString());
    }
    return null;
  }

  public static List<String> getAsStringList(JsonObject o, String member)
      throws JsonSyntaxException {
    if (o.has(member)) {
      if (o.get(member).isJsonArray()) {
        return gson.fromJson(o.get(member), new TypeToken<List<String>>() {}.getType());
      }
      return Lists.newArrayList(o.get(member).getAsString());
    }
    return null;
  }

  public static List<JWSAlgorithm> getAsJwsAlgorithmList(JsonObject o, String member) {
    List<String> strings = getAsStringList(o, member);
    if (strings != null) {
      List<JWSAlgorithm> algs = new ArrayList<>();
      for (String alg : strings) {
        algs.add(JWSAlgorithm.parse(alg));
      }
      return algs;
    }
    return null;
  }

  public static List<JWEAlgorithm> getAsJweAlgorithmList(JsonObject o, String member) {
    List<String> strings = getAsStringList(o, member);
    if (strings != null) {
      List<JWEAlgorithm> algs = new ArrayList<>();
      for (String alg : strings) {
        algs.add(JWEAlgorithm.parse(alg));
      }
      return algs;
    }
    return null;
  }

  public static List<EncryptionMethod> getAsEncryptionMethodList(JsonObject o, String member) {
    List<String> strings = getAsStringList(o, member);
    if (strings != null) {
      List<EncryptionMethod> algs = new ArrayList<>();
      for (String alg : strings) {
        algs.add(EncryptionMethod.parse(alg));
      }
      return algs;
    }
    return null;
  }

  public static Map<String, Object> readMap(JsonReader reader) throws IOException {
    Map<String, Object> map = new HashMap<>();
    reader.beginObject();
    while (reader.hasNext()) {
      String name = reader.nextName();
      Object value = null;
      switch (reader.peek()) {
        case STRING:
          value = reader.nextString();
          break;
        case BOOLEAN:
          value = reader.nextBoolean();
          break;
        case NUMBER:
          value = reader.nextLong();
          break;
        default:
          logger.debug("Found unexpected entry");
          reader.skipValue();
          continue;
      }
      map.put(name, value);
    }
    reader.endObject();
    return map;
  }

  public static Set<Object> readSet(JsonReader reader) throws IOException {
    Set<Object> arraySet = null;
    reader.beginArray();
    switch (reader.peek()) {
      case STRING:
        arraySet = new HashSet<>();
        while (reader.hasNext()) {
          arraySet.add(reader.nextString());
        }
        break;
      case NUMBER:
        arraySet = new HashSet<>();
        while (reader.hasNext()) {
          arraySet.add(reader.nextLong());
        }
        break;
      default:
        arraySet = new HashSet<>();
        break;
    }
    reader.endArray();
    return arraySet;
  }

  public static void writeNullSafeArray(JsonWriter writer, Set<String> items) throws IOException {
    if (items != null) {
      writer.beginArray();
      for (String s : items) {
        writer.value(s);
      }
      writer.endArray();
    } else {
      writer.nullValue();
    }
  }

}
