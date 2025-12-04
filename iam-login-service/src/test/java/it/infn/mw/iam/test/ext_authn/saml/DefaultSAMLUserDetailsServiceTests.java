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
package it.infn.mw.iam.test.ext_authn.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.saml.DefaultSAMLUserDetailsService;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolutionResult;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@RunWith(MockitoJUnitRunner.class)
public class DefaultSAMLUserDetailsServiceTests {

  @Mock
  private IamAccountRepository repo;

  @Mock
  private SamlUserIdentifierResolver resolver;

  @Mock
  private InactiveAccountAuthenticationHander handler;

  private DefaultSAMLUserDetailsService service;

  @Before
  public void setup() {
    service = new DefaultSAMLUserDetailsService(resolver, repo, handler);
  }

  @Test
  public void loadUserBySAMLFindsAccountRegardlessOfSamlIdOrder() {
    SAMLCredential credential = mock(SAMLCredential.class);

    IamSamlId firstId = new IamSamlId("first", "first", "first");
    IamSamlId secondId = new IamSamlId("second", "second", "second");

    List<IamSamlId> samlIds = Arrays.asList(firstId, secondId);

    SamlUserIdentifierResolutionResult resolvedIds = mock(SamlUserIdentifierResolutionResult.class);
    when(resolver.resolveSamlUserIdentifier(credential)).thenReturn(resolvedIds);
    when(resolvedIds.getResolvedIds()).thenReturn(samlIds);

    IamAccount account = new IamAccount();
    account.setUsername("testsamluser");
    account.setPassword("password");
    account.setAuthorities(Set.of(new IamAuthority("ROLE_USER")));
    when(repo.findBySamlId(firstId)).thenReturn(Optional.empty());
    when(repo.findBySamlId(secondId)).thenReturn(Optional.of(account));

    Object userDetails = service.loadUserBySAML(credential);

    assertNotNull(userDetails);
    assertEquals("testsamluser", ((UserDetails) userDetails).getUsername());
    verify(repo).findBySamlId(firstId);
    verify(repo).findBySamlId(secondId);
  }
}
