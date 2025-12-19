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
package it.infn.mw.iam.test.ext_authn.saml.jit_account_provisioning;

import static it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolutionResult.success;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.DEFAULT_IDP_ID;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T1_EPUID;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T1_GIVEN_NAME;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T1_MAIL;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T1_SN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.saml.JustInTimeProvisioningSAMLUserDetailsService;
import it.infn.mw.iam.authn.saml.MappingPropertiesResolver;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolutionResult;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.AttributeMappingProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport;

@ExtendWith(MockitoExtension.class)
class JitUserDetailServiceTests extends JitUserDetailsServiceTestsSupport {

  @Mock
  private IamAccountRepository accountRepo;

  @Mock
  private IamAccountService accountService;

  @Mock
  private SamlUserIdentifierResolver resolver;

  @Mock
  private InactiveAccountAuthenticationHander inactiveAccountHander;

  @Mock
  private MappingPropertiesResolver mpResolver;

  private JustInTimeProvisioningSAMLUserDetailsService userDetailsService;

  @Mock
  private SAMLCredential cred;

  @BeforeEach
  void setup() {

    lenient().when(accountRepo.findBySamlId(any())).thenReturn(Optional.empty());
    lenient().when(accountService.createAccount(any())).thenAnswer(invocation -> {
      IamAccount account = (IamAccount) invocation.getArguments()[0];
      account.setPassword("password");
      return account;
    });

    lenient().when(resolver.resolveSamlUserIdentifier(any()))
      .thenReturn(SamlUserIdentifierResolutionResult.failure(List.of("No suitable user id found")));

    AttributeMappingProperties defaultMappingProps = new AttributeMappingProperties();

    lenient().when(mpResolver.resolveMappingProperties(Mockito.any()))
      .thenReturn(defaultMappingProps);

    userDetailsService = new JustInTimeProvisioningSAMLUserDetailsService(resolver, accountService,
        inactiveAccountHander, accountRepo, Optional.empty(), mpResolver);
  }

  @Test
  void testNullSamlCredential() {
    NullPointerException e =
        assertThrows(NullPointerException.class, () -> userDetailsService.loadUserBySAML(null));
    assertThat(e.getMessage(), equalTo("null saml credential"));
  }

  @Test
  void testUnresolvedSamlIdSanityChecks() {

    UsernameNotFoundException e = assertThrows(UsernameNotFoundException.class,
        () -> userDetailsService.loadUserBySAML(cred));
    assertThat(e.getMessage(),
        equalTo("Could not extract a user identifier from the SAML assertion"));
  }

  @Test
  void testMissingEmailSamlCredentialSanityCheck() {
    lenient().when(resolver.resolveSamlUserIdentifier(cred))
      .thenReturn(success(List.of(T1_SAML_ID)));
    UsernameNotFoundException e = assertThrows(UsernameNotFoundException.class,
        () -> userDetailsService.loadUserBySAML(cred));
    assertThat(e.getMessage(), containsString(String.format("missing required attribute: %s (%s)",
        Saml2Attribute.MAIL.getAlias(), Saml2Attribute.MAIL.getAttributeName())));
  }

  @Test
  void testMissingGivenNameSamlCredentialSanityCheck() {
    lenient().when(resolver.resolveSamlUserIdentifier(cred))
      .thenReturn(success(List.of(T1_SAML_ID)));
    lenient().when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn(T1_MAIL);

    UsernameNotFoundException e = assertThrows(UsernameNotFoundException.class,
        () -> userDetailsService.loadUserBySAML(cred));
    assertThat(e.getMessage(), containsString(String.format("missing required attribute: %s (%s)",
        Saml2Attribute.GIVEN_NAME.getAlias(), Saml2Attribute.GIVEN_NAME.getAttributeName())));
  }

  @Test
  void testMissingFamilyNameSamlCredentialSanityCheck() {
    lenient().when(resolver.resolveSamlUserIdentifier(cred))
      .thenReturn(success(List.of(T1_SAML_ID)));
    lenient().when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn(T1_MAIL);
    lenient().when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn(T1_GIVEN_NAME);

    UsernameNotFoundException e = assertThrows(UsernameNotFoundException.class,
        () -> userDetailsService.loadUserBySAML(cred));
    assertThat(e.getMessage(), containsString(String.format("missing required attribute: %s (%s)",
        Saml2Attribute.SN.getAlias(), Saml2Attribute.SN.getAttributeName())));
  }

  @Test
  void testSamlIdIsUsedForUsername() {
    lenient().when(resolver.resolveSamlUserIdentifier(cred))
      .thenReturn(success(List.of(T1_SAML_ID)));
    lenient().when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn(T1_MAIL);
    lenient().when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn(T1_GIVEN_NAME);
    lenient().when(cred.getAttributeAsString(Saml2Attribute.SN.getAttributeName()))
      .thenReturn(T1_SN);

    User user = (User) userDetailsService.loadUserBySAML(cred);
    assertThat(user.getUsername(), equalTo(T1_EPUID));

  }

  @Test
  void uuidIsUsedForAccountUsernameIfResolvedIdLongerThan128Chars() {
    lenient().when(resolver.resolveSamlUserIdentifier(cred))
      .thenReturn(success(List.of(LONG_SAML_ID)));
    lenient().when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn(T1_MAIL);
    lenient().when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn(T1_GIVEN_NAME);
    lenient().when(cred.getAttributeAsString(Saml2Attribute.SN.getAttributeName()))
      .thenReturn(T1_SN);

    User user = (User) userDetailsService.loadUserBySAML(cred);
    assertThat(user.getUsername().length(), equalTo(36));
  }

  @Test
  void testEntityIdSanityChecksWorkForUntrustedIdp() {
    Set<String> trustedIdps = Sets.newHashSet("http://trusted.idp.example");
    userDetailsService = new JustInTimeProvisioningSAMLUserDetailsService(resolver, accountService,
        inactiveAccountHander, accountRepo, Optional.of(trustedIdps), mpResolver);

    lenient().when(resolver.resolveSamlUserIdentifier(cred))
      .thenReturn(success(List.of(T1_SAML_ID)));
    lenient().when(cred.getRemoteEntityID())
      .thenReturn(SamlAuthenticationTestSupport.DEFAULT_IDP_ID);

    UsernameNotFoundException e = assertThrows(UsernameNotFoundException.class,
        () -> userDetailsService.loadUserBySAML(cred));
    assertThat(e.getMessage(),
        containsString(String.format("SAML credential issuer '%s' is not trusted",
            SamlAuthenticationTestSupport.DEFAULT_IDP_ID)));
  }

  @Test
  void testEntityIdSanityChecksWorkForTrustedIdp() {
    Set<String> trustedIdps = Sets.newHashSet("http://trusted.idp.example", DEFAULT_IDP_ID);
    userDetailsService = new JustInTimeProvisioningSAMLUserDetailsService(resolver, accountService,
        inactiveAccountHander, accountRepo, Optional.of(trustedIdps), mpResolver);

    lenient().when(resolver.resolveSamlUserIdentifier(cred))
      .thenReturn(success(List.of(T1_SAML_ID)));
    lenient().when(cred.getRemoteEntityID())
      .thenReturn(SamlAuthenticationTestSupport.DEFAULT_IDP_ID);
    lenient().when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn(T1_MAIL);
    lenient().when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn(T1_GIVEN_NAME);
    lenient().when(cred.getAttributeAsString(Saml2Attribute.SN.getAttributeName()))
      .thenReturn(T1_SN);

    User user = (User) userDetailsService.loadUserBySAML(cred);
    assertThat(user.getUsername(), equalTo(T1_EPUID));
  }
}
