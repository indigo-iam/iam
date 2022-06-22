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
package it.infn.mw.iam.test.oauth.scope;

import static com.google.common.collect.Sets.newHashSet;
import static it.infn.mw.iam.core.oauth.scope.matchers.StringEqualsScopeMatcher.stringEqualsMatcher;
import static it.infn.mw.iam.core.oauth.scope.matchers.StructuredPathScopeMatcher.structuredPathMatcher;
import static java.util.Collections.emptySet;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod.SECRET_BASIC;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.exception.ValidationException;
import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.core.oidc.IamClientValidationService;

@RunWith(MockitoJUnitRunner.class)
public class DynClientScopeValidationTests {

  @Mock
  SystemScopeService scopeService;

  @Mock
  ScopeMatcherRegistry registry;

  @Spy
  ClientDetailsEntity client = new ClientDetailsEntity();

  @Mock
  ConfigurationPropertiesBean config;

  @Mock
  BlacklistedSiteService blacklistService;

  @Mock
  ClientDetailsEntityService clientService;

  @InjectMocks
  IamClientValidationService clientValidationService;

  @Before
  public void setup() {

    client.setScope(newHashSet("openid", "profile"));
    client.setGrantTypes(newHashSet("authorization_code"));
    client.setRedirectUris(newHashSet("https://test.example/cb"));
    client.setTokenEndpointAuthMethod(SECRET_BASIC);

    when(scopeService.getRestricted()).thenReturn(emptySet());

    // when(registry.findMatcherForScope("openid")).thenReturn(stringEqualsMatcher("openid"));
    // when(registry.findMatcherForScope("profile")).thenReturn(stringEqualsMatcher("profile"));
    when(registry.findMatcherForScope("restricted")).thenReturn(stringEqualsMatcher("restricted"));

    when(clientService.generateClientSecret(Mockito.any())).thenAnswer(i -> i.getArguments()[0]);
  }

  @Test
  public void noFilterTest() throws ValidationException {
    client = clientValidationService.validateClient(client);
    assertThat(client.getScope(), hasSize(2));
    assertThat(client.getScope(), hasItem("openid"));
    assertThat(client.getScope(), hasItem("profile"));
  }

  @Test
  public void staticRestrictedScopeFilterTest() throws ValidationException {
    client.setScope(newHashSet("openid", "profile", "restricted"));

    when(scopeService.getRestricted()).thenReturn(Sets.newHashSet(new SystemScope("restricted")));


    client = clientValidationService.validateClient(client);
    assertThat(client.getScope(), hasSize(2));
    assertThat(client.getScope(), hasItem("openid"));
    assertThat(client.getScope(), hasItem("profile"));
  }
  
  @Test
  public void staticStructuredScopeFilterTest() throws ValidationException {
    client.setScope(newHashSet("openid", "profile", "read", "read:/", "read:/sub/path"));

    when(scopeService.getRestricted()).thenReturn(newHashSet(new SystemScope("read:/")));
    
    when(registry.findMatcherForScope("read:/")).thenReturn(structuredPathMatcher("read", "/"));
    // when(registry.findMatcherForScope("read:/sub/path")).thenReturn(structuredPathMatcher("read",
    // "/"));
    

    client = clientValidationService.validateClient(client);
    assertThat(client.getScope(), hasSize(3));
    assertThat(client.getScope(), hasItem("openid"));
    assertThat(client.getScope(), hasItem("profile"));
    assertThat(client.getScope(), hasItem("read"));
  }
}
