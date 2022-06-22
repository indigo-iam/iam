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
package it.infn.mw.iam.test.ext_authn;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.authn.DefaultExternalAuthenticationHintService;
import it.infn.mw.iam.authn.error.InvalidExternalAuthenticationHintError;

@RunWith(MockitoJUnitRunner.class)
public class ExternalAuthenticationHintServiceTests {

  public static final String BASE_URL = "http://localhost:8080";

  DefaultExternalAuthenticationHintService service =
      new DefaultExternalAuthenticationHintService(BASE_URL);

  @Test(expected = InvalidExternalAuthenticationHintError.class)
  public void testNullExternalAuthnHint() {
    service.resolve(null);
  }

  @Test(expected = InvalidExternalAuthenticationHintError.class)
  public void testEmptyExternalAuthnHint() {
    service.resolve("");
  }

  @Test(expected = InvalidExternalAuthenticationHintError.class)
  public void testSpacesExternalAuthnHint() {
    service.resolve("   ");
  }


  @Test(expected = InvalidExternalAuthenticationHintError.class)
  public void testInvalidSchemeHint() {
    service.resolve("whatever:sdsdad");
  }

  @Test
  public void testSamlWorks() {
    String url = service.resolve("saml:example");
    assertThat(url, is(String.format("%s/saml/login?idp=example", BASE_URL)));
  }
  
  @Test
  public void testSamlDiscoveryWorks() {
    String url = service.resolve("saml:");
    assertThat(url, is(String.format("%s/saml/login", BASE_URL)));
  }

}
