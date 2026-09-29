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
package it.infn.mw.iam.api.scim.model;

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;

import java.io.IOException;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType;

/**
 * Deserializes both the historical IAM user PATCH representation and path-based native values.
 *
 * <p>
 * The historical representation puts a partial {@link ScimUser} directly in {@code value} and
 * omits {@code path}. Some clients instead identify an attribute with {@code path} and send that
 * attribute's native JSON value. Supported path-based values are converted to the same partial-user
 * representation consumed by the existing updater pipeline. Unsupported paths remain attached to
 * the operation so that the updater rejects them explicitly, and pathless requests remain
 * unchanged.
 * </p>
 */
public class ScimUserPatchOperationDeserializer
    extends JsonDeserializer<ScimPatchOperation<ScimUser>> {

  private static final String EXTENSION_PATH_PREFIX = "extension.";

  private static final Pattern EMAIL_VALUE_PATH = Pattern.compile(
      "^emails(?:\\[type\\s+eq\\s+\"work\"\\])?\\.value$",
      Pattern.CASE_INSENSITIVE);

  private static final Pattern PHOTO_VALUE_PATH = Pattern.compile(
      "^photos(?:\\[type\\s+eq\\s+\"photo\"\\])?\\.value$",
      Pattern.CASE_INSENSITIVE);

  @Override
  public ScimPatchOperation<ScimUser> deserialize(JsonParser parser,
      com.fasterxml.jackson.databind.DeserializationContext context) throws IOException {

    ObjectCodec codec = parser.getCodec();
    JsonNode operationNode = codec.readTree(parser);
    JsonNode opNode = operationNode.get("op");
    ScimPatchOperationType operationType = opNode == null || opNode.isNull() ? null
        : codec.treeToValue(opNode, ScimPatchOperationType.class);

    JsonNode pathNode = operationNode.get("path");
    String path = pathNode == null || pathNode.isNull() ? null : pathNode.asText();
    JsonNode valueNode = operationNode.get("value");

    ScimUser value = deserializeValue(parser, codec, path, valueNode);

    ScimPatchOperation.Builder<ScimUser> builder =
        new ScimPatchOperation.Builder<ScimUser>().path(path).value(value);

    if (operationType != null) {
      switch (operationType) {
        case add -> builder.add();
        case remove -> builder.remove();
        case replace -> builder.replace();
      }
    }

    return builder.build();
  }

  private ScimUser deserializeValue(JsonParser parser, ObjectCodec codec, String path,
      JsonNode valueNode) throws IOException {

    if (path == null || path.isBlank()) {
      requireValue(parser, path, valueNode);
      if (!valueNode.isObject()) {
        throw invalidValue(parser, path, "a SCIM user object");
      }
      return codec.treeToValue(valueNode, ScimUser.class);
    }

    String canonicalPath = canonicalPath(path);
    ScimUser.Builder builder = ScimUser.builder();

    switch (canonicalPath) {
      case "username" -> builder.userName(textValue(parser, path, valueNode));
      case "password" -> builder.password(textValue(parser, path, valueNode));
      case "active" -> builder.active(booleanValue(parser, path, valueNode));
      case "name" -> builder.name(nameValue(parser, path, valueNode));
      case "name.givenname" ->
        builder.name(ScimName.builder().givenName(textValue(parser, path, valueNode)).build());
      case "name.familyname" ->
        builder.name(ScimName.builder().familyName(textValue(parser, path, valueNode)).build());
      case "emails" -> addValues(parser, codec, path, valueNode, ScimEmail.class,
          builder::addEmail);
      case "photos" -> addValues(parser, codec, path, valueNode, ScimPhoto.class,
          builder::addPhoto);
      case EXTENSION_PATH_PREFIX + "serviceaccount" ->
        builder.serviceAccount(booleanValue(parser, path, valueNode));
      case EXTENSION_PATH_PREFIX + "affiliation" ->
        builder.affiliation(textValue(parser, path, valueNode));
      case EXTENSION_PATH_PREFIX + "sshkeys" -> addValues(parser, codec, path, valueNode,
          ScimSshKey.class, builder::addSshKey);
      case EXTENSION_PATH_PREFIX + "oidcids" -> addValues(parser, codec, path, valueNode,
          ScimOidcId.class, builder::addOidcId);
      case EXTENSION_PATH_PREFIX + "samlids" -> addValues(parser, codec, path, valueNode,
          ScimSamlId.class, builder::addSamlId);
      case EXTENSION_PATH_PREFIX + "certificates" -> addValues(parser, codec, path, valueNode,
          ScimX509Certificate.class, builder::addX509Certificate);
      default -> {
        if (EMAIL_VALUE_PATH.matcher(canonicalPath).matches()) {
          builder.addEmail(ScimEmail.builder()
            .email(textValue(parser, path, valueNode))
            .build());
        } else if (PHOTO_VALUE_PATH.matcher(canonicalPath).matches()) {
          builder.addPhoto(ScimPhoto.builder()
            .value(textValue(parser, path, valueNode))
            .build());
        } else {
          // Let the updater layer return the existing SCIM "operation not supported"
          // response for paths that IAM does not implement. This avoids accepting and
          // silently ignoring a value while retaining the path for the error message.
          return builder.build();
        }
      }
    }

    return builder.build();
  }

  private static String canonicalPath(String path) {

    String result = path.trim();
    String corePrefix = ScimUser.USER_SCHEMA + ':';
    String extensionColonPrefix = INDIGO_USER_SCHEMA + ':';

    if (startsWithIgnoreCase(result, corePrefix)) {
      result = result.substring(corePrefix.length());
    } else if (startsWithIgnoreCase(result, extensionColonPrefix)) {
      result = EXTENSION_PATH_PREFIX + result.substring(extensionColonPrefix.length());
    }

    return result.toLowerCase(Locale.ROOT);
  }

  private static boolean startsWithIgnoreCase(String value, String prefix) {
    return value.regionMatches(true, 0, prefix, 0, prefix.length());
  }

  private static ScimName nameValue(JsonParser parser, String path, JsonNode valueNode)
      throws JsonMappingException {

    requireValue(parser, path, valueNode);
    if (!valueNode.isObject()) {
      throw invalidValue(parser, path, "an object containing givenName or familyName");
    }

    ScimName.Builder builder = ScimName.builder();
    boolean supportedValueFound = false;
    Iterator<Entry<String, JsonNode>> fields = valueNode.fields();

    while (fields.hasNext()) {
      Entry<String, JsonNode> field = fields.next();
      if ("givenName".equalsIgnoreCase(field.getKey())) {
        builder.givenName(textValue(parser, path + ".givenName", field.getValue()));
        supportedValueFound = true;
      } else if ("familyName".equalsIgnoreCase(field.getKey())) {
        builder.familyName(textValue(parser, path + ".familyName", field.getValue()));
        supportedValueFound = true;
      } else {
        throw invalidValue(parser, path,
            "an object containing only the supported givenName and familyName attributes");
      }
    }

    if (!supportedValueFound) {
      throw invalidValue(parser, path, "an object containing givenName or familyName");
    }

    return builder.build();
  }

  private static <T> void addValues(JsonParser parser, ObjectCodec codec, String path,
      JsonNode valueNode, Class<T> valueType, Consumer<T> consumer) throws IOException {

    requireValue(parser, path, valueNode);

    if (valueNode.isArray()) {
      for (JsonNode item : valueNode) {
        if (!item.isObject()) {
          throw invalidValue(parser, path, "an object or array of objects");
        }
        consumer.accept(codec.treeToValue(item, valueType));
      }
      return;
    }

    if (valueNode.isObject()) {
      consumer.accept(codec.treeToValue(valueNode, valueType));
      return;
    }

    throw invalidValue(parser, path, "an object or array of objects");
  }

  private static String textValue(JsonParser parser, String path, JsonNode valueNode)
      throws JsonMappingException {

    requireValue(parser, path, valueNode);
    if (!valueNode.isTextual()) {
      throw invalidValue(parser, path, "a string");
    }
    return valueNode.textValue();
  }

  private static boolean booleanValue(JsonParser parser, String path, JsonNode valueNode)
      throws JsonMappingException {

    requireValue(parser, path, valueNode);
    if (!valueNode.isBoolean()) {
      throw invalidValue(parser, path, "a boolean");
    }
    return valueNode.booleanValue();
  }

  private static void requireValue(JsonParser parser, String path, JsonNode valueNode)
      throws JsonMappingException {

    if (valueNode == null || valueNode.isMissingNode() || valueNode.isNull()) {
      throw invalidValue(parser, path, "a non-null value");
    }
  }

  private static JsonMappingException invalidValue(JsonParser parser, String path,
      String expected) {

    String target = path == null || path.isBlank() ? "the resource" : "path '" + path + "'";
    return JsonMappingException.from(parser,
        "Invalid SCIM PATCH value for " + target + ": expected " + expected);
  }
}
