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
package it.infn.mw.iam.test.repository;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;


@RunWith(SpringRunner.class)
@IamNoMvcTest
public class IamAccountRepositoryTests {

  static final IamSamlId TEST_USER_ID = new IamSamlId("https://idptestbed/idp/shibboleth",
      Saml2Attribute.EPUID.getAttributeName(), "78901@idptestbed");

  @Autowired
  private IamAccountRepository repo;

  @Test
  public void testSamlIdResolutionWorksAsExpected() {

    IamAccount testUserAccount = repo.findBySamlId(TEST_USER_ID)
      .orElseThrow(() -> new AssertionError("Could not lookup test user by SAML id"));

    assertThat(testUserAccount.getUsername(), equalTo("test"));
  }

}
