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
package it.infn.mw.iam.test.api;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;

import org.springframework.test.web.servlet.ResultMatcher;

import com.fasterxml.jackson.core.type.TypeReference;

import it.infn.mw.iam.api.common.LabelDTO;

public class TestSupport {

  public static final ResultMatcher OK = status().isOk();
  public static final ResultMatcher NO_CONTENT = status().isNoContent();
  public static final ResultMatcher BAD_REQUEST = status().isBadRequest();
  public static final ResultMatcher UNAUTHORIZED = status().isUnauthorized();
  public static final ResultMatcher FORBIDDEN = status().isForbidden();
  public static final ResultMatcher NOT_FOUND = status().isNotFound();
  public static final ResultMatcher CREATED = status().isCreated();


  public static final String RANDOM_UUID = UUID.randomUUID().toString();

  public static final String TEST_001_GROUP_UUID = "c617d586-54e6-411d-8e38-649677980001";
  public static final String TEST_002_GROUP_UUID = "c617d586-54e6-411d-8e38-649677980002";
  
  public static final String ADMIN_USER = "admin";
  public static final String ADMIN_USER_UUID = "73f16d93-2441-4a50-88ff-85360d78c6b5";

  public static final String TEST_USER = "test";
  public static final String TEST_USER_UUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";

  public static final String TEST_100_USER = "test_100";
  public static final String TEST_100_USER_UUID = "f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a";

  public static final String EXPECTED_ACCOUNT_NOT_FOUND = "Expected account not found";
  public static final String EXPECTED_GROUP_NOT_FOUND = "Expected group not found";

  public static String LABEL_PREFIX = "indigo-iam.github.io";
  public static String LABEL_NAME = "example.label";
  public static String LABEL_VALUE = "example-label-value";

  public static LabelDTO TEST_LABEL =
      LabelDTO.builder().prefix(LABEL_PREFIX).name(LABEL_NAME).value(LABEL_VALUE).build();

  public static final TypeReference<List<LabelDTO>> LIST_OF_LABEL_DTO =
      new TypeReference<List<LabelDTO>>() {};

  public static final ResultMatcher INVALID_PREFIX_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid prefix (does not match"));

  public static final ResultMatcher PREFIX_TOO_LONG_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid prefix length"));

  public static final ResultMatcher NAME_REQUIRED_ERROR_MESSAGE =
      jsonPath("$.error", containsString("name is required"));

  public static final ResultMatcher INVALID_NAME_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid name (does not match"));


  public static final ResultMatcher NAME_TOO_LONG_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid name length"));

  public static final ResultMatcher VALUE_TOO_LONG_ERROR_MESSAGE =
      jsonPath("$.error", containsString("invalid value length"));

}
