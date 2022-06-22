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
package it.infn.mw.voms;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.asn1.VOMSACUtils;
import org.italiangrid.voms.request.VOMSResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import com.google.common.collect.Lists;

import it.infn.mw.iam.authn.x509.DefaultX509AuthenticationCredentialExtractor;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.voms.properties.VomsProperties;


public class TestSupport {

  public static final String VOMS_ROLE_LABEL = "voms.role";

  public static final String SERVER_NAME = "voms.example";
  public static final String TLS_PROTOCOL = "TLSv1.2";
  public static final String VERIFY_SUCCESS = "SUCCESS";

  public static final String TEST_0_SUBJECT = "CN=test0,O=IGI,C=IT";
  public static final String TEST_0_ISSUER = "CN=IGI TEST CA,O=IGI,C=IT";
  public static final String TEST_0_SERIAL = "09";
  public static final String TEST_0_V_START = "Sep 26 15:39:34 2012 GMT";
  public static final String TEST_0_V_END = "Sep 24 15:39:34 2022 GMT";


  public static final String TEST_0_EEC_PATH = "/certs/test0.cert.pem";
  public static final String TEST = "test";
  public static final String EXPECTED_USER_NOT_FOUND = "Expected user not found";

  public static final String VO_NAME = "test";

  public static final Instant NOW = Instant.parse("2018-01-01T00:00:00.00Z");
  public static final Instant NOW_PLUS_12_HOURS = NOW.plus(Duration.ofHours(12));

  public static final Instant NOW_PLUS_1_HOUR = NOW.plus(Duration.ofHours(1));

  public static final IamAttribute TEST_ATTRIBUTE = IamAttribute.newInstance("test", "test");

  @TestConfiguration
  static class TestConf {
    @Bean
    @Primary
    public Clock mockClock() {
      return Clock.fixed(NOW, ZoneId.systemDefault());
    }
  }

  @Autowired
  MockMvc mvc;

  @Autowired
  protected Clock clock;

  @Autowired
  protected IamAccountRepository accountRepo;

  @Autowired
  protected IamGroupRepository groupRepo;

  @Autowired
  protected VomsProperties props;

  public static HttpHeaders test0VOMSHeaders() throws IOException {

    String eec = TestUtils.loadClasspathResourceContent(TEST_0_EEC_PATH);

    HttpHeaders headers = new HttpHeaders();

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.CLIENT_CERT.getHeader(), eec);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.SUBJECT.getHeader(),
        TEST_0_SUBJECT);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.ISSUER.getHeader(),
        TEST_0_ISSUER);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.EEC_SUBJECT_DN.getHeader(),
        TEST_0_SUBJECT);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.EEC_ISSUER_DN.getHeader(),
        TEST_0_ISSUER);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.SERIAL.getHeader(),
        TEST_0_SERIAL);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.V_START.getHeader(),
        TEST_0_V_START);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.V_END.getHeader(),
        TEST_0_V_END);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.PROTOCOL.getHeader(),
        TLS_PROTOCOL);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.SERVER_NAME.getHeader(),
        SERVER_NAME);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.VERIFY.getHeader(),
        VERIFY_SUCCESS);

    headers.add(DefaultX509AuthenticationCredentialExtractor.Headers.EEC.getHeader(), eec);

    return headers;
  }

  protected Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  protected VOMSAttribute getAttributeCertificate(VOMSResponse response) throws IOException {

    ASN1InputStream asn1InputStream = new ASN1InputStream(response.getAC());

    AttributeCertificate attributeCertificate = null;

    attributeCertificate = AttributeCertificate.getInstance(asn1InputStream.readObject());

    asn1InputStream.close();

    return VOMSACUtils.deserializeVOMSAttributes(attributeCertificate);
  }



  protected IamAccount setupTestUser() {
    IamAccount testAccount =
        accountRepo.findByUsername(TEST).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamX509Certificate cert = new IamX509Certificate();
    cert.setLabel("label");
    cert.setSubjectDn(TEST_0_SUBJECT);
    cert.setIssuerDn(TEST_0_ISSUER);

    List<IamX509Certificate> certs = Lists.newArrayList(cert);
    testAccount.linkX509Certificates(certs);
    accountRepo.save(testAccount);

    return testAccount;
  }

  protected IamGroup createVomsRootGroup() {
    return createGroup(props.getAa().getVoName());
  }

  protected IamGroup createGroup(String name) {

    Date now = Date.from(clock.instant());
    IamGroup g = new IamGroup();
    g.setName(name);
    g.setUuid(UUID.randomUUID().toString());
    g.setCreationTime(now);
    g.setLastUpdateTime(now);
    groupRepo.save(g);
    return g;
  }

  protected IamGroup createChildGroup(IamGroup parent, String name) {

    Date now = Date.from(clock.instant());
    IamGroup g = new IamGroup();
    g.setName(String.format("%s/%s", parent.getName(), name));
    g.setUuid(UUID.randomUUID().toString());
    g.setCreationTime(now);
    g.setLastUpdateTime(now);
    g.setParentGroup(parent);
    parent.getChildrenGroups().add(g);
    groupRepo.save(g);
    groupRepo.save(parent);
    return g;
  }

  protected IamAccount addAccountToGroup(IamAccount a, IamGroup g) {

    Optional<IamGroup> maybeGroup =
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(a.getUuid(), g.getUuid());

    if (!maybeGroup.isPresent()) {
      a.getGroups().add(IamAccountGroupMembership.forAccountAndGroup(clock.instant(), a, g));

      accountRepo.save(a);

    }

    return a;
  }

  protected IamGroup createRoleGroup(IamGroup parent, String name) {
    IamGroup g = createChildGroup(parent, name);
    g.getLabels().add(IamLabel.builder().name(VOMS_ROLE_LABEL).build());
    groupRepo.save(g);
    return g;
  }

  protected IamAccount assignGenericAttribute(IamAccount a, IamAttribute attribute) {
    a.getAttributes().remove(attribute);
    a.getAttributes().add(attribute);
    accountRepo.save(a);

    return a;
  }
}
