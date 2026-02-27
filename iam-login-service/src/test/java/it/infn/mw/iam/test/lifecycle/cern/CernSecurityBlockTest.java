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
package it.infn.mw.iam.test.lifecycle.cern;

import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_STATUS;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;

import java.time.Clock;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.client.response.MockRestResponseCreators;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mercateo.test.clock.TestClock;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernSecurityBlockingError;
import it.infn.mw.iam.api.registration.cern.DefaultCernSecurityBlockingService;
import it.infn.mw.iam.api.registration.cern.CernSecurityBlockingApiService;
import it.infn.mw.iam.api.registration.cern.dto.CernTokenResponse;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernSecurityBlockingHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernStatus;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
  CernSecurityBlockTest.TestConfig.class})
@TestPropertySource(properties = {
  // @formatter:off
  "cern.task.pageSize=5",
  // @formatter:on
})
@ActiveProfiles(value = {"h2-test", "cern"})
class CernSecurityBlockTest extends TestSupport
  implements LifecycleTestSupport {

    @TestConfiguration
    public static class TestConfig {
        @Bean
        @Primary
        Clock mockClock() {
            return TestClock.fixed(NOW, ZoneId.systemDefault());
        }

        @Bean
        @Primary
        CernSecurityBlockingApiService blockingService() {
            return mock(CernSecurityBlockingApiService.class);
        }

        @Bean
        @Primary
        CernHrDBApiService hrDb() {
        return mock(CernHrDBApiService.class);
        }

        @Bean
        @Primary
        RestTemplateFactory mockRestTemplateFactory() {
          return new MockRestTemplateFactory();
        }
    }
    @Autowired
    IamAccountRepository repo;

    @Autowired
    IamAccountService service;

    @Autowired
    CernSecurityBlockingHandler cernSecurityBlockingHandler;

    // tokenResponse bean removed; not injected

    @Autowired
    CernSecurityBlockingApiService blockingService;

    @Autowired
    CernHrDBApiService hrDb;
      
    @Autowired
    CernHrLifecycleHandler cernHrLifecycleHandler;

    @Autowired
    Clock clock;

    @Autowired
    RestTemplateFactory rtf;

    MockRestTemplateFactory mockRtf;
    RestTemplate restTemplate;
    CernProperties props;
    DefaultCernSecurityBlockingService svc;
    IamAccount cernUser;

    @BeforeEach
    void init() {
        mockRtf = (MockRestTemplateFactory) rtf;
        mockRtf.resetTemplate();
        restTemplate = mockRtf.newRestTemplate();

        cernUser = IamAccount.newAccount();
        cernUser.setUsername(CERN_USER);
        cernUser.setUuid(CERN_USER_UUID);
        cernUser.setActive(true);
        cernUser.setEndTime(Date.from(NOW.plus(165, ChronoUnit.DAYS)));
        cernUser.getUserInfo().setEmail(CERN_USER + "@example");
        cernUser.getUserInfo().setGivenName("cern");
        cernUser.getUserInfo().setFamilyName("user");
        cernUser.getUserInfo().setEmailVerified(true);
        service.createAccount(cernUser);
        service.addLabel(cernUser, cernPersonIdLabel(CERN_PERSON_ID));

        props = new CernProperties();
        CernProperties.CernBlockingProperties b = new CernProperties.CernBlockingProperties();
        b.setClientId("cid");
        b.setClientSecret("secret");
        b.setAudience("aud");
        b.setTokenUrl("https://token.url");
        b.setAuthorizationUrl("http://authorization.test.example");
        b.setGracePeriod(10);
        props.setBlocking(b);
        
        svc = new DefaultCernSecurityBlockingService(rtf, props);
        
        // Pre-cache token to avoid token fetch during tests
        try {
          java.lang.reflect.Field cachedTokenField = DefaultCernSecurityBlockingService.class
              .getDeclaredField("cachedToken");
          cachedTokenField.setAccessible(true);
          cachedTokenField.set(svc, "test-access-token");
          
          java.lang.reflect.Field tokenExpiryField = DefaultCernSecurityBlockingService.class
              .getDeclaredField("tokenExpiry");
          tokenExpiryField.setAccessible(true);
          tokenExpiryField.set(svc, java.time.Instant.now().plusSeconds(3600));
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
    }

    @AfterEach
    void teardown() {
        reset(blockingService);
        reset(hrDb);
        service.deleteAccount(cernUser);
    }
    
    private IamAccount loadAccount(String username) {
        return repo.findByUuid(username).orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));
    }

    @Test
    void testPaginationWorks() {

        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPerson(String.valueOf(new Random().nextLong() % 100L))));
        
        Pageable pageRequest = PageRequest.of(0, 5, Direction.ASC, "username");
        Page<IamAccount> accountPage = repo.findAll(pageRequest);

        for (IamAccount account : accountPage.getContent()) {
            service.addLabel(account, cernPersonIdLabel(UUID.randomUUID().toString()));
        }

        cernSecurityBlockingHandler.run();

        accountPage = repo.findAll(pageRequest);
        System.out.println("Account: " + accountPage.getContent().size()); 
     
        for (IamAccount account : accountPage.getContent()) {
            assertThat(account.isActive(), is(true));
            System.out.println("Account: " + account.getLabels());
        }
        assertThat(accountPage.getContent().size(), is(5));
    }
    @Test
    void testUserSuspensionWorks() {

        IamAccount testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(true));
        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPersonSecurityDto(CERN_PERSON_ID, cernUser, true)));
        
        cernSecurityBlockingHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(false));
        Optional<IamLabel> cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(cernStatusLabel.get().getValue(), is(CernStatus.BLOCKED.name()));
    }
    @Test
    void testUserBlockedNoAction() {

        IamAccount testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(true));
        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPersonSecurityDto(CERN_PERSON_ID, cernUser, true)));
        
        cernSecurityBlockingHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(false));
        Optional<IamLabel> cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(cernStatusLabel.get().getValue(), is(CernStatus.BLOCKED.name()));
        
        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPersonSecurityDto(CERN_PERSON_ID, cernUser, true)));

        cernSecurityBlockingHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(false));

        Optional<IamLabel> cernStatusLabel2 = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(cernStatusLabel2.get().getValue(), is(CernStatus.BLOCKED.name()));
    }
    
    @Test
    void testUserRestorationWorks() {

        IamAccount testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(true));
        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPersonSecurityDto(CERN_PERSON_ID, cernUser, true)));
        
        cernSecurityBlockingHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(false));
        Optional<IamLabel> cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(cernStatusLabel.get().getValue(), is(CernStatus.BLOCKED.name()));
        
        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPersonSecurityDto(CERN_PERSON_ID, cernUser, false)));

        cernSecurityBlockingHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(true));

        Optional<IamLabel> cernStatusLabel2 = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(cernStatusLabel2.get().getValue(), is(CernStatus.VO_MEMBER.name()));
    }

    @Test
    void testUserSuspensionWithHRdb() {

        IamAccount testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(true));
        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPersonSecurityDto(CERN_PERSON_ID, cernUser, true)));
        
        cernSecurityBlockingHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(false));
        Optional<IamLabel> cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(cernStatusLabel.get().getValue(), is(CernStatus.BLOCKED.name()));

        VOPersonDTO voPerson = voPerson(CERN_PERSON_ID);
        when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(voPerson));

        cernHrLifecycleHandler.run();

        assertThat(testAccount.isActive(), is(false));
        Optional<IamLabel> cernStatusLabel2 = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(cernStatusLabel2.get().getValue(), is(CernStatus.BLOCKED.name()));
    }

    @Test
    void testUserRestorationWorksWithHRDb() {

        IamAccount testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(true));

        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPersonSecurityDto(CERN_PERSON_ID, cernUser, true)));
        
        cernSecurityBlockingHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        assertThat(testAccount.isActive(), is(false));
        Optional<IamLabel> cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(cernStatusLabel.get().getValue(), is(CernStatus.BLOCKED.name()));

        when(blockingService.getSecurityBlockingRecord(anyString()))
          .thenReturn(Optional.of(voPersonSecurityDto(CERN_PERSON_ID, cernUser, false)));

        cernSecurityBlockingHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(testAccount.isActive(), is(true));
        assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));

        VOPersonDTO voPerson = voPerson(CERN_PERSON_ID);
        when(hrDb.getHrDbPersonRecord(CERN_PERSON_ID)).thenReturn(Optional.of(voPerson));

        cernHrLifecycleHandler.run();

        testAccount = loadAccount(CERN_USER_UUID);
        cernStatusLabel = testAccount.getLabelByPrefixAndName(LABEL_CERN_PREFIX, LABEL_STATUS);
        assertThat(testAccount.isActive(), is(true));
        assertThat(cernStatusLabel.get().getValue(), is(CernStatus.VO_MEMBER.name()));
        assertThat(cernStatusLabel.get().getValue(), is(not(CernStatus.BLOCKED.name())));
    }

    @Test
    void testApiErrorIsHandled() {

      when(blockingService.getSecurityBlockingRecord(anyString()))
        .thenThrow(new CernSecurityBlockingError("API is unreachable"));

      cernSecurityBlockingHandler.run();

      IamAccount testAccount = loadAccount(CERN_USER_UUID);

      assertThat(testAccount.isActive(), is(true));

    }


    @Test
    void cernTokenResponseDefaults() throws Exception {
      CernTokenResponse r = new CernTokenResponse();
      assertNull(r.getAccessToken());
      assertEquals(0L, r.getExpiresIn());
      assertNull(r.getTokenType());

      String json = "{" +
          "\"access_token\":\"abc123\"," +
          "\"expires_in\":456," +
          "\"token_type\":\"bearer\"" +
          "}";
      ObjectMapper om = new ObjectMapper();
      CernTokenResponse r2 = om.readValue(json, CernTokenResponse.class);
      assertEquals("abc123", r2.getAccessToken());
      assertEquals(456L, r2.getExpiresIn());
      assertEquals("bearer", r2.getTokenType());
    }

    @Test
    void cernTokenResponseSerialization() throws Exception {
      CernTokenResponse r = new CernTokenResponse();
      java.lang.reflect.Field at = CernTokenResponse.class.getDeclaredField("accessToken");
      at.setAccessible(true);
      at.set(r, "foo");
      java.lang.reflect.Field ei = CernTokenResponse.class.getDeclaredField("expiresIn");
      ei.setAccessible(true);
      ei.setLong(r, 789L);
      java.lang.reflect.Field tt = CernTokenResponse.class.getDeclaredField("tokenType");
      tt.setAccessible(true);
      tt.set(r, "bearer test");

      ObjectMapper om = new ObjectMapper();
      String out = om.writeValueAsString(r);
      assertTrue(out.contains("\"access_token\":\"foo\""));
      assertTrue(out.contains("\"expires_in\":789"));
      assertTrue(out.contains("\"token_type\":\"bearer test\""));
    }

    @Test
    void testBuildAuthHeaders() throws Exception {
      java.lang.reflect.Field cachedTokenField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("cachedToken");
      cachedTokenField.setAccessible(true);
      cachedTokenField.set(svc, "test-token-xyz");
      
      java.lang.reflect.Field tokenExpiryField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("tokenExpiry");
      tokenExpiryField.setAccessible(true);
      tokenExpiryField.set(svc, java.time.Instant.now().plusSeconds(3600));
      
      Method buildAuthHeaders = DefaultCernSecurityBlockingService.class
          .getDeclaredMethod("buildAuthHeaders");
      buildAuthHeaders.setAccessible(true);
      HttpHeaders headers = (HttpHeaders) buildAuthHeaders.invoke(svc);

      assertEquals("Bearer test-token-xyz", headers.get("Authorization").get(0));
    }

    @Test
    void testGetSecurityBlockingRecordSuccess() throws Exception {
      VOPersonDTO voPerson = voPerson("12345");
      voPerson.setBlocked(false);
      
      MockRestServiceServer mockServer = mockRtf.getMockServer();
      ObjectMapper om = new ObjectMapper();
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withSuccess(om.writeValueAsString(voPerson), 
              org.springframework.http.MediaType.APPLICATION_JSON));
      
      Optional<VOPersonDTO> result = svc.getSecurityBlockingRecord("testuser");
      
      mockServer.verify();
      assertTrue(result.isPresent());
      assertEquals(voPerson.getBlocked(), result.get().getBlocked());
    }

    @Test
    void testGetSecurityBlockingRecordNotFound() {
      MockRestServiceServer mockServer = mockRtf.getMockServer();
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withStatus(org.springframework.http.HttpStatus.NOT_FOUND));
      
      Optional<VOPersonDTO> result = svc.getSecurityBlockingRecord("nonexistent");
      
      mockServer.verify();
      assertFalse(result.isPresent());
    }

    @Test
    void testGetSecurityBlockingRecordError() {
      MockRestServiceServer mockServer = mockRtf.getMockServer();
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withStatus(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR));
      
      CernSecurityBlockingError exception = assertThrows(CernSecurityBlockingError.class, () -> {
        svc.getSecurityBlockingRecord("testuser");
      });
      
      mockServer.verify();
      assertTrue(exception.getMessage().contains("Error fetching security blocking record"));
    }
}

        
