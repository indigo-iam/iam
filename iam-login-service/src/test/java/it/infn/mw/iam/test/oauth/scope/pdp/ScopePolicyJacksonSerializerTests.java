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
package it.infn.mw.iam.test.oauth.scope.pdp;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;

import it.infn.mw.iam.audit.utils.IamScopePolicySerializer;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;

@RunWith(JUnit4.class)
@Transactional
public class ScopePolicyJacksonSerializerTests extends ScopePolicyTestUtils {

  public static final String REPR1 =
      "{\"id\":null,\"description\":null,\"rule\":\"PERMIT\",\"matching_policy\":\"EQ\",\"account\":null,\"group\":null,\"scopes\":[]}";

  public static final String REPR2 = 
      "{\"id\":null,\"description\":null,\"rule\":\"PERMIT\",\"matching_policy\":\"EQ\",\"account\":{\"uuid\":\"f5f009ca-30b6-48d1-bb6a-b976b1a95525\",\"name\":\"test\"},\"group\":null,\"scopes\":[]}";

  @Test
  public void testJacksonSerializationHandlesNull() throws IOException {
    ObjectMapper mapper = new ObjectMapper();

    Writer jsonWriter = new StringWriter();
    JsonGenerator jsonGenerator = new JsonFactory().createGenerator(jsonWriter);
    SerializerProvider serializerProvider = mapper.getSerializerProvider();

    IamScopePolicySerializer serializer = new IamScopePolicySerializer();
    IamScopePolicy p = initPermitScopePolicy();

    serializer.serialize(p, jsonGenerator, serializerProvider);
    jsonGenerator.flush();

    assertThat(jsonWriter.toString(), is(REPR1));
  }

  @Test
  public void testJacksonSerialization() throws IOException {
    ObjectMapper mapper = new ObjectMapper();

    Writer jsonWriter = new StringWriter();
    JsonGenerator jsonGenerator = new JsonFactory().createGenerator(jsonWriter);
    SerializerProvider serializerProvider = mapper.getSerializerProvider();

    IamScopePolicySerializer serializer = new IamScopePolicySerializer();
    IamScopePolicy p = initPermitScopePolicy();

    IamAccount account = new IamAccount();
    account.setUuid("f5f009ca-30b6-48d1-bb6a-b976b1a95525");
    account.setUsername("test");

    p.setAccount(account);

    serializer.serialize(p, jsonGenerator, serializerProvider);
    jsonGenerator.flush();

    assertThat(jsonWriter.toString(), is(REPR2));
  }

}
