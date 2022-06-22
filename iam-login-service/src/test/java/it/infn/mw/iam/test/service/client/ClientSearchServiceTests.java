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
package it.infn.mw.iam.test.service.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.validation.ConstraintViolationException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.search.ClientSearchForm;
import it.infn.mw.iam.api.client.search.service.ClientSearchService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;

@IamNoMvcTest
@SpringBootTest(classes = {IamLoginService.class, ClientTestConfig.class},
    webEnvironment = WebEnvironment.NONE)
public class ClientSearchServiceTests {

  @Autowired
  private ClientSearchService service;

  @Test
  public void testParamValidation() {
    
    assertThrows(ConstraintViolationException.class, () -> {
      ClientSearchForm form = new ClientSearchForm();
      form.setSearch(null);
      service.searchClients(form);
    });

    assertThrows(ConstraintViolationException.class, () -> {
      ClientSearchForm form = new ClientSearchForm();
      form.setSearch("");
      service.searchClients(form);
    });


    Assertions.assertDoesNotThrow(() -> {
      ClientSearchForm form = new ClientSearchForm();
      form.setSearch("term");
      service.searchClients(form);
    });

  }

  @Test
  public void testSimpleSearch() {

    ClientSearchForm form = new ClientSearchForm();
    form.setSearch("scim");

    ListResponseDTO<RegisteredClientDTO> result =
        service.searchClients(form);

    assertThat(result.getTotalResults(), is(2L));


  }

}
