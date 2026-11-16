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
package it.infn.mw.iam.test.registration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.userinfo.IamUserInfoInterceptor;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@SpringBootTest
class IamUserInfoInterceptorTests {

  @Autowired
  Clock clock;

  private IamAccountService accountService;
  private IamUserInfoInterceptor interceptor;

  @BeforeEach
  void setUp() {
    accountService = mock(IamAccountService.class);
    interceptor = new IamUserInfoInterceptor(accountService);
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void preHandleShouldSafelySerializeFamilyName() throws Exception {

    String username = "test-user";
    String familyName = "<script>alert('XSS')</script>";

    IamUserInfo userInfo = new IamUserInfo();
    userInfo.setGivenName("Test");
    userInfo.setFamilyName(familyName);

    IamAccount account = new IamAccount();
    account.setUuid("test-uuid");
    account.setUsername(username);
    account.setUserInfo(userInfo);
    account.setLastUpdateTime(Date.from(clock.instant()));

    userInfo.setIamAccount(account);

    when(accountService.findByUsername(username)).thenReturn(Optional.of(account));

    Authentication authentication = mock(Authentication.class);
    when(authentication.getName()).thenReturn(username);
    when(authentication.getAuthorities()).thenReturn(new ArrayList<>());

    SecurityContextHolder.getContext().setAuthentication(authentication);

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    boolean result = interceptor.preHandle(request, response, new Object());

    assertTrue(result);
    assertSame(userInfo, request.getAttribute(IamUserInfoInterceptor.USERINFO_ATTR_NAME));

    String json = (String) request.getAttribute(IamUserInfoInterceptor.USERINFO_JSON_ATTR_NAME);

    assertNotNull(json);
    assertFalse(json.contains("<"));
    assertFalse(json.contains(">"));
    assertFalse(json.contains("</script>"));

    JsonObject parsed = JsonParser.parseString(json).getAsJsonObject();

    assertEquals(familyName, parsed.get("family_name").getAsString());
  }
}
