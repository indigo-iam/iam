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
package it.infn.mw.iam.test.core.userinfo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.gson.JsonParser;

import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.userinfo.IamUserInfoInterceptor;

class IamUserInfoInterceptorTests {

  private final IamUserInfoInterceptor interceptor =
      new IamUserInfoInterceptor(mock(IamAccountService.class));

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  static Stream<Collection<? extends GrantedAuthority>> authorities() {
    return Stream.of(Collections.emptyList(), List.of(),
        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
        List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
  }

  @ParameterizedTest
  @MethodSource("authorities")
  void serializesAuthorities(Collection<? extends GrantedAuthority> authorities) throws Exception {
    String json = serialize(authorities);
    assertThat(JsonParser.parseString(json).getAsJsonArray().size()).isEqualTo(authorities.size());
    int index = 0;
    for (GrantedAuthority authority : authorities) {
      assertThat(JsonParser.parseString(json).getAsJsonArray().get(index++).getAsString())
        .isEqualTo(authority.getAuthority());
    }
    if (authorities.isEmpty()) {
      assertThat(json).isEqualTo("[]");
    }
  }

  @Test
  void preservesHtmlSafeEscapingForInlineScripts() throws Exception {
    String authority = "</script><script>alert('x')</script>&=\"\\\n";
    String json = serialize(List.of(new SimpleGrantedAuthority(authority)));
    assertThat(json).doesNotContain("<", ">", "&", "=", "'");
    assertThat(JsonParser.parseString(json).getAsJsonArray().get(0).getAsString())
      .isEqualTo(authority);
  }

  @Test
  void leavesAuthoritiesUnsetWithoutAuthentication() throws Exception {
    SecurityContextHolder.clearContext();
    MockHttpServletRequest request = new MockHttpServletRequest();
    assertThat(interceptor.preHandle(request, new MockHttpServletResponse(), new Object()))
      .isTrue();
    assertThat(request.getAttribute("userAuthorities")).isNull();
  }

  private String serialize(Collection<? extends GrantedAuthority> authorities) throws Exception {
    Authentication authentication = mock(Authentication.class);
    // Keep the original collection implementation to reproduce the EmptyList failure.
    doReturn(authorities).when(authentication).getAuthorities();
    SecurityContextHolder.getContext().setAuthentication(authentication);
    MockHttpServletRequest request = new MockHttpServletRequest();
    assertThat(interceptor.preHandle(request, new MockHttpServletResponse(), new Object()))
      .isTrue();
    return (String) request.getAttribute("userAuthorities");
  }
}
