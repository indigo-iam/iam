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
package it.infn.mw.iam.test.oauth.profile;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.EnumSet;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamTokenEnhancerProperties;
import it.infn.mw.iam.config.IamTokenEnhancerProperties.IncludeLabelProperties;
import it.infn.mw.iam.config.IamTokenEnhancerProperties.TokenContext;
import it.infn.mw.iam.config.scim.ScimProperties.LabelDescriptor;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.ScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.iam.IamIdTokenCustomizer;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.SavedUserAuthentication;

@SuppressWarnings("deprecation")
class IamIdTokenCustomizerTests {

  @Mock
  private IamProperties properties;

  @Mock
  private ClaimValueHelper claimValueHelper;

  @Mock
  private ScopeClaimTranslationService scopeClaimTranslationService;

  @Mock
  private IamAccount account;

  private TestIamIdTokenCustomizer customizer;

  @BeforeEach
  void setup() {
    MockitoAnnotations.openMocks(this);

    customizer =
        new TestIamIdTokenCustomizer(properties, claimValueHelper, scopeClaimTranslationService);
  }

  @Test
  void isExternalAuthnReturnsTrueForSamlAuthentication() {
    SavedUserAuthentication authentication = mock(SavedUserAuthentication.class);

    when(authentication.getSourceClass())
      .thenReturn(SamlExternalAuthenticationToken.class.getName());

    assertTrue(customizer.testIsExternalAuthn(authentication));
  }

  @Test
  void isExternalAuthnReturnsTrueForOidcAuthentication() {
    SavedUserAuthentication authentication = mock(SavedUserAuthentication.class);

    when(authentication.getSourceClass())
      .thenReturn(OidcExternalAuthenticationToken.class.getName());

    assertTrue(customizer.testIsExternalAuthn(authentication));
  }

  @Test
  void isExternalAuthnReturnsFalseForDifferentSourceClass() {
    SavedUserAuthentication authentication = mock(SavedUserAuthentication.class);

    when(authentication.getSourceClass())
      .thenReturn(UsernamePasswordAuthenticationToken.class.getName());

    assertFalse(customizer.testIsExternalAuthn(authentication));
  }

  @Test
  void isExternalAuthnReturnsFalseWhenSourceClassIsNull() {
    SavedUserAuthentication authentication = mock(SavedUserAuthentication.class);

    when(authentication.getSourceClass()).thenReturn(null);

    assertFalse(customizer.testIsExternalAuthn(authentication));
  }

  @Test
  void isExternalAuthnReturnsFalseForNonSavedAuthentication() {
    Authentication authentication = new UsernamePasswordAuthenticationToken("user", "password");

    assertFalse(customizer.testIsExternalAuthn(authentication));
  }

  @Test
  void includeExternalAuthnAddsClaimForExternalAuthentication() {
    Builder claims = mock(Builder.class);
    OAuth2AccessTokenEntity accessToken = mock(OAuth2AccessTokenEntity.class);

    SavedUserAuthentication authentication = mock(SavedUserAuthentication.class);

    when(authentication.getSourceClass())
      .thenReturn(OidcExternalAuthenticationToken.class.getName());

    AuthenticationHolderEntity entity = mock(AuthenticationHolderEntity.class);
    OAuth2Authentication oauth2auth = mock(OAuth2Authentication.class);

    when(accessToken.getAuthenticationHolder()).thenReturn(entity);
    when(entity.getAuthentication()).thenReturn(oauth2auth);
    when(oauth2auth.getUserAuthentication()).thenReturn(authentication);

    Object externalAuthnClaim = mock(Object.class);

    when(claimValueHelper.resolveClaim(eq(IamExtraClaimNames.EXTERNAL_AUTHN), eq(oauth2auth),
        eq(Optional.of(account)))).thenReturn(externalAuthnClaim);

    customizer.testIncludeExternalAuthnInIdToken(claims, accessToken, account);

    verify(claims).claim(IamExtraClaimNames.EXTERNAL_AUTHN, externalAuthnClaim);
  }

  @Test
  void includeExternalAuthnDoesNothingForNonExternalAuthentication() {
    Builder claims = mock(Builder.class);
    OAuth2AccessTokenEntity accessToken = mock(OAuth2AccessTokenEntity.class);

    AuthenticationHolderEntity entity = mock(AuthenticationHolderEntity.class);
    OAuth2Authentication oauth2auth = mock(OAuth2Authentication.class);
    SavedUserAuthentication authentication = mock(SavedUserAuthentication.class);

    when(authentication.getSourceClass())
      .thenReturn(UsernamePasswordAuthenticationToken.class.getName());
    when(accessToken.getAuthenticationHolder()).thenReturn(entity);
    when(entity.getAuthentication()).thenReturn(oauth2auth);
    when(oauth2auth.getUserAuthentication()).thenReturn(authentication);

    customizer.testIncludeExternalAuthnInIdToken(claims, accessToken, account);

    verify(claimValueHelper, never()).resolveClaim(eq(IamExtraClaimNames.EXTERNAL_AUTHN), any(),
        any());

    verify(claims, never()).claim(eq(IamExtraClaimNames.EXTERNAL_AUTHN), any());
  }

  @Test
  void includeLabelsAddsConfiguredLabelToIdToken() {
    Builder claims = mock(Builder.class);
    IncludeLabelProperties includeLabel = mock(IncludeLabelProperties.class);
    IamTokenEnhancerProperties tokenEnhancer = mock(IamTokenEnhancerProperties.class);

    LabelDescriptor descriptor = new LabelDescriptor();
    descriptor.setPrefix("example");
    descriptor.setName("role");

    when(properties.getTokenEnhancer()).thenReturn(tokenEnhancer);

    when(tokenEnhancer.getIncludeLabels()).thenReturn(List.of(includeLabel));

    when(includeLabel.getContext()).thenReturn(EnumSet.of(TokenContext.ID_TOKEN));

    when(includeLabel.getLabel()).thenReturn(descriptor);

    when(includeLabel.getClaimName()).thenReturn("example_role");

    IamLabel label = mock(IamLabel.class);
    when(label.getValue()).thenReturn("admin");

    when(account.getLabelByPrefixAndName("example", "role")).thenReturn(Optional.of(label));

    customizer.testIncludeLabelsInIdToken(claims, account);

    verify(claims).claim("example_role", "admin");
  }

  @Test
  void includeLabelsDoesNotAddClaimWhenLabelIsMissing() {
    Builder claims = mock(Builder.class);
    IncludeLabelProperties includeLabel = mock(IncludeLabelProperties.class);
    IamTokenEnhancerProperties tokenEnhancer = mock(IamTokenEnhancerProperties.class);

    LabelDescriptor descriptor = new LabelDescriptor();
    descriptor.setPrefix("example");
    descriptor.setName("role");

    when(properties.getTokenEnhancer()).thenReturn(tokenEnhancer);

    when(tokenEnhancer.getIncludeLabels()).thenReturn(List.of(includeLabel));

    when(includeLabel.getContext()).thenReturn(EnumSet.of(TokenContext.ID_TOKEN));

    when(includeLabel.getLabel()).thenReturn(descriptor);

    when(account.getLabelByPrefixAndName("example", "role")).thenReturn(Optional.empty());

    customizer.testIncludeLabelsInIdToken(claims, account);

    verify(claims, never()).claim(any(), any());
  }

  @Test
  void includeLabelsIgnoresLabelsNotConfiguredForIdToken() {
    Builder claims = mock(Builder.class);
    IncludeLabelProperties includeLabel = mock(IncludeLabelProperties.class);
    IamTokenEnhancerProperties tokenEnhancer = mock(IamTokenEnhancerProperties.class);
    LabelDescriptor descriptor = new LabelDescriptor();
    descriptor.setPrefix("example");
    descriptor.setName("role");

    when(properties.getTokenEnhancer()).thenReturn(tokenEnhancer);
    when(tokenEnhancer.getIncludeLabels()).thenReturn(List.of(includeLabel));
    when(includeLabel.getLabel()).thenReturn(descriptor);

    when(includeLabel.getContext()).thenReturn(EnumSet.of(TokenContext.USERINFO));

    customizer.testIncludeLabelsInIdToken(claims, account);

    verify(account, never()).getLabelByPrefixAndName(any(), any());

    verify(claims, never()).claim(any(), any());
  }

  private static class TestIamIdTokenCustomizer extends IamIdTokenCustomizer {

    TestIamIdTokenCustomizer(IamProperties properties, ClaimValueHelper claimValueHelper,
        ScopeClaimTranslationService scopeClaimTranslationService) {

      super(properties, claimValueHelper, scopeClaimTranslationService);
    }

    boolean testIsExternalAuthn(Authentication authentication) {
      return isExternalAuthn(authentication);
    }

    void testIncludeExternalAuthnInIdToken(Builder claims, OAuth2AccessTokenEntity accessToken,
        IamAccount account) {

      includeExternalAuthnInIdToken(claims, accessToken, account);
    }

    void testIncludeLabelsInIdToken(Builder claims, IamAccount account) {
      includeLabelsInIdToken(claims, account);
    }
  }
}
