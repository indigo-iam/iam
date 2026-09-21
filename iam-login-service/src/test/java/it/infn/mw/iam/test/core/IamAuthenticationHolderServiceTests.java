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
package it.infn.mw.iam.test.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.authn.ExternalAuthenticationInfoBuilder;
import it.infn.mw.iam.authn.oidc.OIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.IamAuthenticationHolderService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.SavedUserAuthentication;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class IamAuthenticationHolderServiceTests {

  @InjectMocks
  private IamAuthenticationHolderService authnHolderService;

  @Mock
  private ExternalAuthenticationInfoBuilder mapBuilder;

  @Mock
  private ClientDetailsEntity client;

  @Mock
  private IamAuthenticationHolderRepository repo;

  @Test
  void shouldPreserveExternalAuthenticationAndAarcInfoAfterMfa() {
    String username = "test-user";
    String homeOrganization = "example.org";
    String externalAffiliation = "researcher@example.org";

    Map<String, String> aarcInfo =
        Map.of("urn:oid:1.3.6.1.4.1.25178.1.2.9", homeOrganization, "EPSA", externalAffiliation);

    OIDCAuthenticationToken oidcToken = mock(OIDCAuthenticationToken.class);

    OidcExternalAuthenticationToken externalToken =
        new OidcExternalAuthenticationToken(oidcToken, username, "credentials");

    when(externalToken.buildAuthnInfoMap(mapBuilder)).thenReturn(aarcInfo);

    // Authentication returned after MFA
    ExtendedAuthenticationToken mfaToken = new ExtendedAuthenticationToken(username, "credentials",
        Set.of(new SimpleGrantedAuthority("ROLE_USER")));

    mfaToken.setAuthenticated(true);
    mfaToken.setExternalAuthentication(externalToken);

    OAuth2Request o2Request = mock(OAuth2Request.class);
    when(o2Request.getAuthorities()).thenReturn(Collections.emptySet());

    OAuth2Authentication oauth2Authentication = new OAuth2Authentication(o2Request, mfaToken);

    AuthenticationHolderEntity holder = authnHolderService.create(oauth2Authentication, client);

    SavedUserAuthentication saved = holder.getUserAuth();

    assertThat(saved).isNotNull();
    assertThat(saved.getSourceClass()).isEqualTo(OidcExternalAuthenticationToken.class.getName());
    assertThat(saved.getAdditionalInfo()).containsEntry("urn:oid:1.3.6.1.4.1.25178.1.2.9",
        homeOrganization);
    assertThat(saved.getAdditionalInfo()).containsEntry("EPSA", externalAffiliation);
  }
}
