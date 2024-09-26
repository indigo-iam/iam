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
package it.infn.mw.iam.test.scim.user;

import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CONTENT_TYPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.buildUser;
import static it.infn.mw.iam.test.scim.ScimUtils.buildUserWithPassword;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.hamcrest.collection.IsIterableContainingInAnyOrder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.aup.AupService;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.SshKeyUtils;
import it.infn.mw.iam.test.X509Utils;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {"scim.include_authorities=true"})
public class ScimUserCreationTests extends ScimUserTestSupport {

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private PasswordEncoder encoder;

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private AupService aupService;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationAccessDeletion() throws Exception {

    ScimUser user = buildUser("paul_mccartney", "test@email.test", "Paul", "McCartney").build();
    ScimUser createdUser = scimUtils.postUser(user);

    assertThat(user.getUserName(), equalTo(createdUser.getUserName()));
    assertThat(user.getEmails(), hasSize(equalTo(1)));
    assertThat(user.getEmails().get(0).getValue(),
        equalTo(createdUser.getEmails().get(0).getValue()));
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithPassword() throws Exception {

    ScimUser user =
        buildUserWithPassword("john_lennon", "password", "lennon@email.test", "John", "Lennon")
          .build();

    ScimUser createdUser = scimUtils.postUser(user);

    assertNull(createdUser.getPassword());

    Optional<IamAccount> createdAccount = accountRepo.findByUuid(createdUser.getId());
    if (!createdAccount.isPresent()) {
      Assert.fail("Account not created");
    }

    assertThat(createdAccount.get().getPassword(), notNullValue());
    assertThat(encoder.matches("password", createdAccount.get().getPassword()), equalTo(true));
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithOidcAccount() throws Exception {

    ScimUser user = ScimUser.builder("user_with_oidc")
      .buildEmail("test_user@test.org")
      .buildName("User", "With OIDC Account")
      .buildOidcId("urn:oidc:test:issuer", "1234")
      .active(true)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo("urn:oidc:test:issuer"));
    assertThat(createdUser.getIndigoUser().getOidcIds().get(0).getSubject(), equalTo("1234"));

    createdUser = scimUtils.getUser(createdUser.getId());
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo("urn:oidc:test:issuer"));
    assertThat(createdUser.getIndigoUser().getOidcIds().get(0).getSubject(), equalTo("1234"));
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithStolenOidcAccountFailure() throws Exception {

    ScimUser user = ScimUser.builder("user_with_oidc")
      .buildEmail("test_user@test.org")
      .buildName("User", "With OIDC Account")
      .buildOidcId("urn:oidc:test:issuer", "1234")
      .active(true)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getOidcIds(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getOidcIds().get(0).getIssuer(),
        equalTo("urn:oidc:test:issuer"));
    assertThat(createdUser.getIndigoUser().getOidcIds().get(0).getSubject(), equalTo("1234"));

    ScimUser anotherUser = ScimUser.builder("another_user_with_oidc")
      .buildEmail("another_test_user@test.org")
      .buildName("Another User", "With OIDC Account")
      .buildOidcId("urn:oidc:test:issuer", "1234")
      .active(true)
      .build();


    mvc
      .perform(post(ScimUtils.getUsersLocation()).content(mapper.writeValueAsBytes(anotherUser))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.detail", containsString("already bound to a user")));

  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithSshKey() throws Exception {

    ScimUser user = ScimUser.builder("user_with_sshkey")
      .buildEmail("test_user@test.org")
      .buildName("User", "With ssh key Account")
      .buildSshKey("Personal", SshKeyUtils.sshKeys.get(0).key, null, true)
      .active(true)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getDisplay(), equalTo("Personal"));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SshKeyUtils.sshKeys.get(0).key));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SshKeyUtils.sshKeys.get(0).fingerprintSHA256));

    createdUser = scimUtils.getUser(createdUser.getId());
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getDisplay(), equalTo("Personal"));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SshKeyUtils.sshKeys.get(0).key));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SshKeyUtils.sshKeys.get(0).fingerprintSHA256));
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithSshKeyValueOnly() throws Exception {

    ScimUser user = ScimUser.builder("user_with_sshkey")
      .buildEmail("test_user@test.org")
      .buildName("User", "With ssh key Account")
      .addSshKey(ScimSshKey.builder().value(SshKeyUtils.sshKeys.get(0).key).build())
      .active(true)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getDisplay(),
        equalTo(user.getUserName() + "'s personal ssh key"));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SshKeyUtils.sshKeys.get(0).key));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SshKeyUtils.sshKeys.get(0).fingerprintSHA256));

    createdUser = scimUtils.getUser(createdUser.getId());
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getDisplay(),
        equalTo(user.getUserName() + "'s personal ssh key"));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SshKeyUtils.sshKeys.get(0).key));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SshKeyUtils.sshKeys.get(0).fingerprintSHA256));
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithStolenSshKeyFailure() throws Exception {

    ScimUser user = ScimUser.builder("user_with_sshkey")
      .buildEmail("test_user@test.org")
      .buildName("User", "With ssh key")
      .buildSshKey("Personal", SshKeyUtils.sshKeys.get(0).key, null, true)
      .active(true)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getSshKeys(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getDisplay(), equalTo("Personal"));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getValue(),
        equalTo(SshKeyUtils.sshKeys.get(0).key));
    assertThat(createdUser.getIndigoUser().getSshKeys().get(0).getFingerprint(),
        equalTo(SshKeyUtils.sshKeys.get(0).fingerprintSHA256));

    ScimUser anotherUser = ScimUser.builder("another_user_with_sshkey")
      .buildEmail("another_test_user@test.org")
      .buildName("Another User", "With ssh key")
      .buildSshKey("Personal", SshKeyUtils.sshKeys.get(0).key, null, true)
      .active(true)
      .build();

    mvc
      .perform(post(ScimUtils.getUsersLocation()).content(mapper.writeValueAsBytes(anotherUser))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.detail", containsString("already bound to a user")));

  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithSamlId() throws Exception {

    ScimUser user = ScimUser.builder("user_with_samlId")
      .buildEmail("test_user@test.org")
      .buildName("User", "With saml id Account")
      .buildSamlId("IdpID", "UserID")
      .active(true)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getSamlIds().get(0).getIdpId(),
        equalTo(user.getIndigoUser().getSamlIds().get(0).getIdpId()));
    assertThat(createdUser.getIndigoUser().getSamlIds().get(0).getUserId(),
        equalTo(user.getIndigoUser().getSamlIds().get(0).getUserId()));

    createdUser = scimUtils.getUser(createdUser.getId());
    assertNotNull(createdUser.getIndigoUser());
    assertThat(createdUser.getIndigoUser().getSamlIds(), hasSize(equalTo(1)));
    assertThat(createdUser.getIndigoUser().getSamlIds().get(0).getIdpId(),
        equalTo(user.getIndigoUser().getSamlIds().get(0).getIdpId()));
    assertThat(createdUser.getIndigoUser().getSamlIds().get(0).getUserId(),
        equalTo(user.getIndigoUser().getSamlIds().get(0).getUserId()));
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithX509Certificate() throws Exception {

    ScimX509Certificate cert = ScimX509Certificate.builder()
      .display("Personal1")
      .pemEncodedCertificate(X509Utils.x509Certs.get(0).certificate)
      .primary(false)
      .build();

    ScimUser user = ScimUser.builder("user_with_x509")
      .buildEmail("test_user@test.org")
      .buildName("User", "With x509 Certificate")
      .addX509Certificate(cert)
      .active(true)
      .build();

    List<ScimX509Certificate> userCertList = user.getIndigoUser().getCertificates();

    ScimUser createdUser = scimUtils.postUser(user);
    List<ScimX509Certificate> createdUserCertList = createdUser.getIndigoUser().getCertificates();

    assertNotNull(createdUserCertList);
    assertThat(createdUserCertList, hasSize(equalTo(1)));
    assertThat(createdUserCertList.get(0).getDisplay(), equalTo(userCertList.get(0).getDisplay()));
    assertThat(createdUserCertList.get(0).getPemEncodedCertificate(),
        equalTo(userCertList.get(0).getPemEncodedCertificate()));

    createdUser = scimUtils.getUser(createdUser.getId());
    assertNotNull(createdUserCertList);
    assertThat(createdUserCertList, hasSize(equalTo(1)));
    assertThat(createdUserCertList.get(0).getDisplay(), equalTo(userCertList.get(0).getDisplay()));
    assertThat(createdUserCertList.get(0).getPemEncodedCertificate(),
        equalTo(userCertList.get(0).getPemEncodedCertificate()));
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithMultipleX509Certificate() throws Exception {

    ScimX509Certificate cert1 = ScimX509Certificate.builder()
      .display("Personal1")
      .pemEncodedCertificate(X509Utils.x509Certs.get(0).certificate)
      .primary(false)
      .build();

    ScimX509Certificate cert2 = ScimX509Certificate.builder()
      .display("Personal2")
      .pemEncodedCertificate(X509Utils.x509Certs.get(1).certificate)
      .primary(true)
      .build();

    ScimUser user = ScimUser.builder("user_with_x509")
      .buildEmail("test_user@test.org")
      .buildName("User", "With x509 Certificate")
      .addX509Certificate(cert1)
      .addX509Certificate(cert2)
      .active(true)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);
    List<ScimX509Certificate> createdUserCertList = createdUser.getIndigoUser().getCertificates();

    assertNotNull(createdUserCertList);
    assertThat(createdUserCertList.stream().map(c -> c.getDisplay()).collect(Collectors.toList()),
        IsIterableContainingInAnyOrder.containsInAnyOrder("Personal1", "Personal2"));
    ScimX509Certificate createdCert1 = createdUserCertList.stream()
      .filter(cert -> "Personal1".equals(cert.getDisplay()))
      .findFirst()
      .get();
    ScimX509Certificate createdCert2 = createdUserCertList.stream()
      .filter(cert -> "Personal2".equals(cert.getDisplay()))
      .findFirst()
      .get();

    assertThat(createdCert1.getPrimary(), equalTo(FALSE));
    assertThat(createdCert2.getPrimary(), equalTo(TRUE));
    assertThat(createdCert1.getPemEncodedCertificate(),
        equalTo(X509Utils.x509Certs.get(0).certificate));
    assertThat(createdCert2.getPemEncodedCertificate(),
        equalTo(X509Utils.x509Certs.get(1).certificate));

  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithMultipleX509CertificateAndNoPrimary() throws Exception {

    ScimX509Certificate cert1 = ScimX509Certificate.builder()
      .display("Personal1")
      .pemEncodedCertificate(X509Utils.x509Certs.get(0).certificate)
      .primary(false)
      .build();

    ScimX509Certificate cert2 = ScimX509Certificate.builder()
      .display("Personal2")
      .pemEncodedCertificate(X509Utils.x509Certs.get(1).certificate)
      .primary(false)
      .build();

    ScimUser user = ScimUser.builder("user_with_x509")
      .buildEmail("test_user@test.org")
      .buildName("User", "With x509 Certificate")
      .addX509Certificate(cert1)
      .addX509Certificate(cert2)
      .active(true)
      .build();

    ScimUser createdUser = scimUtils.postUser(user);
    List<ScimX509Certificate> createdUserCertList = createdUser.getIndigoUser().getCertificates();

    assertNotNull(createdUserCertList);
    assertThat(createdUserCertList.stream().map(c -> c.getDisplay()).collect(Collectors.toList()),
        IsIterableContainingInAnyOrder.containsInAnyOrder("Personal1", "Personal2"));
    ScimX509Certificate createdCert1 = createdUserCertList.stream()
      .filter(cert -> "Personal1".equals(cert.getDisplay()))
      .findFirst()
      .get();
    ScimX509Certificate createdCert2 = createdUserCertList.stream()
      .filter(cert -> "Personal2".equals(cert.getDisplay()))
      .findFirst()
      .get();

    // One and only one certificate should be primary with no order guarantee
    assertEquals(1, (createdCert1.getPrimary() ? 1 : 0) + (createdCert2.getPrimary() ? 1 : 0));
    assertThat(createdCert1.getPemEncodedCertificate(),
        equalTo(X509Utils.x509Certs.get(0).certificate));
    assertThat(createdCert2.getPemEncodedCertificate(),
        equalTo(X509Utils.x509Certs.get(1).certificate));

  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithEndTimeAndBasicAuthorities() throws Exception {

    Calendar cal = Calendar.getInstance();
    cal.setTime(new Date());
    cal.add(Calendar.HOUR_OF_DAY, 1);
    Date expTime = cal.getTime();

    ScimUser user = buildUser("user_with_exp_time", "userwithexptime@email.test", "User", "Test")
      .endTime(expTime)
      .addAuthority("ROLE_ADMIN")
      .build();
    ScimUser createdUser = scimUtils.postUser(user);

    assertThat(user.getUserName(), equalTo(createdUser.getUserName()));
    assertThat(user.getEmails(), hasSize(equalTo(1)));
    assertThat(user.getEmails().get(0).getValue(),
        equalTo(createdUser.getEmails().get(0).getValue()));
    assertNull(createdUser.getIndigoUser().getEndTime());
    assertThat(createdUser.getIndigoUser().getAuthorities().contains("ROLE_ADMIN"), equalTo(false));
  }

  @Test
  @WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
  public void testUserCreationWithAupSignatureIsIgnored() throws Exception {

    final String AUP_URL = "https://valid.test.url.com/";
    final String AUP_DESCRIPTION = "Test AUP";
    final Date currentDate = new Date();

    AupDTO aup = new AupDTO(AUP_URL, "", AUP_DESCRIPTION, 0L, currentDate, currentDate, "30,15,1");
    aupService.saveAup(aup);

    Calendar cal = Calendar.getInstance();
    cal.setTime(currentDate);
    cal.add(Calendar.HOUR_OF_DAY, 1);
    Date signatureTime = cal.getTime();

    ScimUser user =
        buildUser("user_with_aup_signature", "userwithaupsignature@email.test", "User", "Test")
          .aupSignatureTime(signatureTime)
          .build();
    ScimUser createdUser = scimUtils.postUser(user);

    assertThat(user.getUserName(), equalTo(createdUser.getUserName()));
    assertThat(user.getEmails(), hasSize(equalTo(1)));
    assertThat(user.getEmails().get(0).getValue(),
        equalTo(createdUser.getEmails().get(0).getValue()));
    assertNull(createdUser.getIndigoUser().getAupSignatureTime());

    aupService.deleteAup();
  }
}
