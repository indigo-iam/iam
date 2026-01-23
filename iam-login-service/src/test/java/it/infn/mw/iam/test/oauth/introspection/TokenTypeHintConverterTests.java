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
package it.infn.mw.iam.test.oauth.introspection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHintConverter;

public class TokenTypeHintConverterTests {

  private TokenTypeHintConverter converter = new TokenTypeHintConverter();

  @Test
  public void testTokenTypeHintNullConversion() {

    assertNull(converter.convert(null));
  }

  @Test
  public void testTokenTypeHintLowerCaseConversions() {

    assertEquals(TokenTypeHint.ACCESS_TOKEN, converter.convert("access_token"));
    assertEquals(TokenTypeHint.REFRESH_TOKEN, converter.convert("refresh_token"));
  }

  @Test
  public void testTokenTypeHintUpperCaseConversions() {

    assertEquals(TokenTypeHint.ACCESS_TOKEN, converter.convert("ACCESS_TOKEN"));
    assertEquals(TokenTypeHint.REFRESH_TOKEN, converter.convert("REFRESH_TOKEN"));
  }

  @Test
  public void testTokenTypeHintMixedCaseConversions() {

    assertEquals(TokenTypeHint.ACCESS_TOKEN, converter.convert("ACCESS_token"));
    assertEquals(TokenTypeHint.REFRESH_TOKEN, converter.convert("refresh_TOKEN"));
  }

}
