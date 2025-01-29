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
package it.infn.mw.iam.test.startup;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;

@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@ActiveProfiles({"h2"})
@SpringBootTest(classes = {IamLoginService.class})
@TestPropertySource(properties = {"spring.main.allow-bean-definition-overriding=false"})
public class ApplicationStartupSuccessTests {

  @Autowired
  private ApplicationContext context;

  @Test
  public void testSuccessOnStartupWithBeanDefinitionOverridingIsOff() {
    assertDoesNotThrow(() -> {
      context.getBean(UserApprovalHandler.class);
    });
  }
}
