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

import static it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolutionResult.resolutionSuccess;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.DEFAULT_IDP_ID;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T1_EPUID;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T1_GIVEN_NAME;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T1_MAIL;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.T1_SN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
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

@RunWith(MockitoJUnitRunner.class)
public class JitUserDetailServiceTests extends JitUserDetailsServiceTestsSupport {

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

  @Before
  public void setup() {
    when(accountRepo.findBySamlId(any())).thenReturn(Optional.empty());
    // when(accountRepo.findBySamlId(anyString(), anyString(), anyString()))
    // .thenReturn(Optional.empty());

    when(accountService.createAccount(any())).thenAnswer(invocation -> {
      IamAccount account = (IamAccount) invocation.getArguments()[0];
      account.setPassword("password");
      return account;
    });

    when(resolver.resolveSamlUserIdentifier(any()))
      .thenReturn(SamlUserIdentifierResolutionResult.resolutionFailure("No suitable user id found"));

    AttributeMappingProperties defaultMappingProps = new AttributeMappingProperties();
    
    when(mpResolver.resolveMappingProperties(Mockito.any())).thenReturn(defaultMappingProps);
    
    userDetailsService = new JustInTimeProvisioningSAMLUserDetailsService(resolver, accountService,
        inactiveAccountHander, accountRepo, Optional.empty(), mpResolver);
  }

  @Test(expected = NullPointerException.class)
  public void testNullSamlCredential() {
    try {
      userDetailsService.loadUserBySAML(null);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("null saml credential"));
      throw e;
    }
  }

  @Test(expected = UsernameNotFoundException.class)
  public void testUnresolvedSamlIdSanityChecks() {

    try {
      userDetailsService.loadUserBySAML(cred);
    } catch (UsernameNotFoundException e) {
      assertThat(e.getMessage(),
          equalTo("Could not extract a user identifier from the SAML assertion"));
      throw e;
    }
  }

  @Test(expected = UsernameNotFoundException.class)
  public void testMissingEmailSamlCredentialSanityCheck() {
    when(resolver.resolveSamlUserIdentifier(cred)).thenReturn(resolutionSuccess(T1_SAML_ID));
    try {
      userDetailsService.loadUserBySAML(cred);
    } catch (UsernameNotFoundException e) {

      assertThat(e.getMessage(), containsString(String.format("missing required attribute: %s (%s)",
          Saml2Attribute.MAIL.getAlias(), Saml2Attribute.MAIL.getAttributeName())));
      throw e;
    }
  }

  @Test(expected = UsernameNotFoundException.class)
  public void testMissingGivenNameSamlCredentialSanityCheck() {
    when(resolver.resolveSamlUserIdentifier(cred)).thenReturn(resolutionSuccess(T1_SAML_ID));
    when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName())).thenReturn(T1_MAIL);

    try {
      userDetailsService.loadUserBySAML(cred);
    } catch (UsernameNotFoundException e) {

      assertThat(e.getMessage(), containsString(String.format("missing required attribute: %s (%s)",
          Saml2Attribute.GIVEN_NAME.getAlias(), Saml2Attribute.GIVEN_NAME.getAttributeName())));
      throw e;
    }
  }

  @Test(expected = UsernameNotFoundException.class)
  public void testMissingFamilyNameSamlCredentialSanityCheck() {
    when(resolver.resolveSamlUserIdentifier(cred)).thenReturn(resolutionSuccess(T1_SAML_ID));
    when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName())).thenReturn(T1_MAIL);
    when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn(T1_GIVEN_NAME);

    try {
      userDetailsService.loadUserBySAML(cred);
    } catch (UsernameNotFoundException e) {

      assertThat(e.getMessage(), containsString(String.format("missing required attribute: %s (%s)",
          Saml2Attribute.SN.getAlias(), Saml2Attribute.SN.getAttributeName())));
      throw e;
    }
  }

  @Test
  public void testSamlIdIsUsedForUsername() {
    when(resolver.resolveSamlUserIdentifier(cred)).thenReturn(resolutionSuccess(T1_SAML_ID));
    when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName())).thenReturn(T1_MAIL);
    when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn(T1_GIVEN_NAME);
    when(cred.getAttributeAsString(Saml2Attribute.SN.getAttributeName())).thenReturn(T1_SN);

    User user = (User) userDetailsService.loadUserBySAML(cred);
    assertThat(user.getUsername(), equalTo(T1_EPUID));

  }

  @Test
  public void uuidIsUsedForAccountUsernameIfResolvedIdLongerThan128Chars() {
    when(resolver.resolveSamlUserIdentifier(cred)).thenReturn(resolutionSuccess(LONG_SAML_ID));
    when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName())).thenReturn(T1_MAIL);
    when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn(T1_GIVEN_NAME);
    when(cred.getAttributeAsString(Saml2Attribute.SN.getAttributeName())).thenReturn(T1_SN);

    User user = (User) userDetailsService.loadUserBySAML(cred);
    assertThat(user.getUsername().length(), equalTo(36));
  }

  @Test(expected = UsernameNotFoundException.class)
  public void testEntityIdSanityChecksWorkForUntrustedIdp() {
    Set<String> trustedIdps = Sets.newHashSet("http://trusted.idp.example");
    userDetailsService = new JustInTimeProvisioningSAMLUserDetailsService(resolver, accountService,
        inactiveAccountHander, accountRepo, Optional.of(trustedIdps), mpResolver);

    when(resolver.resolveSamlUserIdentifier(cred)).thenReturn(resolutionSuccess(T1_SAML_ID));
    when(cred.getRemoteEntityID()).thenReturn(SamlAuthenticationTestSupport.DEFAULT_IDP_ID);

    try {
      userDetailsService.loadUserBySAML(cred);
    } catch (UsernameNotFoundException e) {
      assertThat(e.getMessage(),
          containsString(String.format("SAML credential issuer '%s' is not trusted",
              SamlAuthenticationTestSupport.DEFAULT_IDP_ID)));
      throw e;
    }
  }

  @Test
  public void testEntityIdSanityChecksWorkForTrustedIdp() {
    Set<String> trustedIdps = Sets.newHashSet("http://trusted.idp.example", DEFAULT_IDP_ID);
    userDetailsService = new JustInTimeProvisioningSAMLUserDetailsService(resolver, accountService,
        inactiveAccountHander, accountRepo, Optional.of(trustedIdps), mpResolver);

    when(resolver.resolveSamlUserIdentifier(cred)).thenReturn(resolutionSuccess(T1_SAML_ID));
    when(cred.getRemoteEntityID()).thenReturn(SamlAuthenticationTestSupport.DEFAULT_IDP_ID);
    when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName())).thenReturn(T1_MAIL);
    when(cred.getAttributeAsString(Saml2Attribute.GIVEN_NAME.getAttributeName()))
      .thenReturn(T1_GIVEN_NAME);
    when(cred.getAttributeAsString(Saml2Attribute.SN.getAttributeName())).thenReturn(T1_SN);

    User user = (User) userDetailsService.loadUserBySAML(cred);
    assertThat(user.getUsername(), equalTo(T1_EPUID));

  }

}
