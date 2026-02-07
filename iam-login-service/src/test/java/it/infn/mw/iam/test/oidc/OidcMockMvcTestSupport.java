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
package it.infn.mw.iam.test.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest(classes = { IamLoginService.class }, properties = "iam.access_token.store_on_database=false")
@AutoConfigureMockMvc
public abstract class OidcMockMvcTestSupport {

  @Autowired
  protected MockMvc mockMvc;

  protected ObjectMapper mapper;

  @BeforeEach
  void setupMapper() {
    mapper = new ObjectMapper();
  }

  protected MvcResult postForm(String endpoint, Map<String, String> params, String basicAuth)
      throws Exception {

    String body = params.entrySet()
      .stream()
      .map(e -> e.getKey() + "=" + e.getValue())
      .collect(Collectors.joining("&"));

    var request = post(endpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED)
      .content(body)
      .characterEncoding(StandardCharsets.UTF_8);

    if (basicAuth != null) {
      request.header("Authorization", "Basic " + basicAuth);
    }

    return mockMvc.perform(request).andReturn();
  }

  protected JsonNode assert200AndParse(MvcResult result) throws Exception {
    assertEquals(200, result.getResponse().getStatus());
    return mapper.readTree(result.getResponse().getContentAsString());
  }

  protected static String basicAuth(String clientId, String secret) {
    return Base64.getEncoder()
      .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
