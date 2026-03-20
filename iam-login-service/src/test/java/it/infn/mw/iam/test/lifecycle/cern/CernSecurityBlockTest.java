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
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
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
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;

import java.lang.reflect.Method;

import java.time.Clock;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.time.Instant;
import java.lang.reflect.Field; 
import java.lang.reflect.InvocationTargetException;

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

    private void primeToken(DefaultCernSecurityBlockingService service) throws Exception {
      Field cachedTokenField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("cachedToken");
      cachedTokenField.setAccessible(true);
      cachedTokenField.set(service, "test-token");

      Field tokenExpiryField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("tokenExpiry");
      tokenExpiryField.setAccessible(true);
      tokenExpiryField.set(service, java.time.Instant.now().plusSeconds(3600));
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
     
        for (IamAccount account : accountPage.getContent()) {
            assertThat(account.isActive(), is(true));

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
      Field at = CernTokenResponse.class.getDeclaredField("accessToken");
      at.setAccessible(true);
      at.set(r, "foo");
      Field ei = CernTokenResponse.class.getDeclaredField("expiresIn");
      ei.setAccessible(true);
      ei.setLong(r, 789L);
      Field tt = CernTokenResponse.class.getDeclaredField("tokenType");
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
      Field cachedTokenField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("cachedToken");
      cachedTokenField.setAccessible(true);
      cachedTokenField.set(svc, "test-token-xyz");
      
      Field tokenExpiryField = DefaultCernSecurityBlockingService.class
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
      primeToken(svc);

      VOPersonDTO voPerson = voPerson("12345");
      voPerson.setBlocked(false);
      
      String url = String.format("%s%s", props.getBlocking().getAuthorizationUrl(),
                                  "/api/v1.0/Identity/-/Query");
      String personId = "testuser";
      String patch = String.format("{\"operator\":\"Equals\",\"value\":\"%s\",\"property\":\"personId\"}",
                                   personId);

      MockRestServiceServer mockServer = mockRtf.getMockServer();
      ObjectMapper om = new ObjectMapper();
      mockServer.expect(requestTo(url))
          .andExpect(method(POST))
          .andExpect(content().contentType("application/json-patch+json"))
          .andExpect(content().json(patch))
          .andRespond(MockRestResponseCreators.withSuccess(om.writeValueAsString(voPerson), 
              org.springframework.http.MediaType.APPLICATION_JSON));
      
      Optional<VOPersonDTO> result = svc.getSecurityBlockingRecord(personId);
      
      mockServer.verify();
      assertTrue(result.isPresent());
      assertEquals(voPerson.getBlocked(), result.get().getBlocked());
    }

    @Test
    void testGetSecurityBlockingRecordNotFound() throws Exception {
      primeToken(svc);

      String url = String.format("%s%s", props.getBlocking().getAuthorizationUrl(),
                                  "/api/v1.0/Identity/-/Query");
      String personId = "nonexistent";
      String patch = String.format("{\"operator\":\"Equals\",\"value\":\"%s\",\"property\":\"personId\"}",
                                   personId);

      MockRestServiceServer mockServer = mockRtf.getMockServer();
      mockServer.expect(requestTo(url))
          .andExpect(method(POST))
          .andExpect(content().contentType("application/json-patch+json"))
          .andExpect(content().json(patch))
          .andRespond(MockRestResponseCreators.withStatus(org.springframework.http.HttpStatus.NOT_FOUND));
      
      Optional<VOPersonDTO> result = svc.getSecurityBlockingRecord(personId);
      
      mockServer.verify();
      assertFalse(result.isPresent());
    }

    @Test
    void testGetSecurityBlockingRecordError() throws Exception {
      primeToken(svc);

      String url = String.format("%s%s", props.getBlocking().getAuthorizationUrl(),
                                  "/api/v1.0/Identity/-/Query");
      String personId = "testuser";
      String patch = String.format("{\"operator\":\"Equals\",\"value\":\"%s\",\"property\":\"personId\"}",
                                   personId);

      MockRestServiceServer mockServer = mockRtf.getMockServer();
      mockServer.expect(requestTo(url))
          .andExpect(method(POST))
          .andExpect(content().contentType("application/json-patch+json"))
          .andExpect(content().json(patch))
          .andRespond(MockRestResponseCreators.withStatus(INTERNAL_SERVER_ERROR));
      
      CernSecurityBlockingError exception = assertThrows(CernSecurityBlockingError.class, () -> {
        svc.getSecurityBlockingRecord(personId);
      });
      
      mockServer.verify();
      assertTrue(exception.getMessage().contains("Error fetching security blocking record"));
    }

    @Test
    void testGetAccessTokenSuccess() throws Exception {
      DefaultCernSecurityBlockingService freshSvc = new DefaultCernSecurityBlockingService(rtf, props);
      
      MockRestServiceServer mockServer = mockRtf.resetTemplate();
      ObjectMapper om = new ObjectMapper();
      
      CernTokenResponse tokenResponse = new CernTokenResponse();
      Field at = CernTokenResponse.class.getDeclaredField("accessToken");
      at.setAccessible(true);
      at.set(tokenResponse, "new-access-token-12345");
      Field ei = CernTokenResponse.class.getDeclaredField("expiresIn");
      ei.setAccessible(true);
      ei.setLong(tokenResponse, 3600L);
      
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withSuccess(om.writeValueAsString(tokenResponse), APPLICATION_JSON));
      
      Method getAccessToken = DefaultCernSecurityBlockingService.class
          .getDeclaredMethod("getAccessToken");
      getAccessToken.setAccessible(true);
      String token = (String) getAccessToken.invoke(freshSvc);
      
      assertEquals("new-access-token-12345", token);
      mockServer.verify();
    }

    @Test
    void testGetAccessTokenMultipleCalls() throws Exception {

      DefaultCernSecurityBlockingService freshSvc = new DefaultCernSecurityBlockingService(rtf, props);
      
      MockRestServiceServer mockServer = mockRtf.resetTemplate();
      ObjectMapper om = new ObjectMapper();
      
      CernTokenResponse tokenResponse = new CernTokenResponse();
      Field at = CernTokenResponse.class.getDeclaredField("accessToken");
      at.setAccessible(true);
      at.set(tokenResponse, "multi-call-token");
      Field ei = CernTokenResponse.class.getDeclaredField("expiresIn");
      ei.setAccessible(true);
      ei.setLong(tokenResponse, 3600L);
      
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withSuccess(om.writeValueAsString(tokenResponse),APPLICATION_JSON));
      
      Method getAccessToken = DefaultCernSecurityBlockingService.class
          .getDeclaredMethod("getAccessToken");
      getAccessToken.setAccessible(true);
      
      String token1 = (String) getAccessToken.invoke(freshSvc);
      String token2 = (String) getAccessToken.invoke(freshSvc);
      
      assertEquals(token1, token2);
      assertEquals("multi-call-token", token1);
      
      mockServer.verify();
    }

    @Test
    void testGetAccessTokenCached() throws Exception {
      DefaultCernSecurityBlockingService freshSvc = new DefaultCernSecurityBlockingService(rtf, props);
      
      Field cachedTokenField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("cachedToken");
      cachedTokenField.setAccessible(true);
      cachedTokenField.set(freshSvc, "cached-token-xyz");
      
      Field tokenExpiryField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("tokenExpiry");
      tokenExpiryField.setAccessible(true);
      tokenExpiryField.set(freshSvc, java.time.Instant.now().plusSeconds(3600));
      
      Method getAccessToken = DefaultCernSecurityBlockingService.class
          .getDeclaredMethod("getAccessToken");
      getAccessToken.setAccessible(true);
      String token = (String) getAccessToken.invoke(freshSvc);
      
      assertEquals("cached-token-xyz", token);
    }

    @Test
    void testGetAccessTokenExpiredRefetch() throws Exception {
      DefaultCernSecurityBlockingService freshSvc = new DefaultCernSecurityBlockingService(rtf, props);
      
      Field cachedTokenField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("cachedToken");
      cachedTokenField.setAccessible(true);
      cachedTokenField.set(freshSvc, "expired-token");
      
      Field tokenExpiryField = DefaultCernSecurityBlockingService.class
          .getDeclaredField("tokenExpiry");
      tokenExpiryField.setAccessible(true);
      tokenExpiryField.set(freshSvc, Instant.now().minusSeconds(100));
      
      MockRestServiceServer mockServer = mockRtf.resetTemplate();
      ObjectMapper om = new ObjectMapper();
      
      CernTokenResponse tokenResponse = new CernTokenResponse();
      Field at = CernTokenResponse.class.getDeclaredField("accessToken");
      at.setAccessible(true);
      at.set(tokenResponse, "new-refreshed-token");
      Field ei = CernTokenResponse.class.getDeclaredField("expiresIn");
      ei.setAccessible(true);
      ei.setLong(tokenResponse, 3600L);
      
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withSuccess(om.writeValueAsString(tokenResponse), APPLICATION_JSON));
      
      Method getAccessToken = DefaultCernSecurityBlockingService.class
          .getDeclaredMethod("getAccessToken");
      getAccessToken.setAccessible(true);
      String token = (String) getAccessToken.invoke(freshSvc);
      
      assertEquals("new-refreshed-token", token);
      mockServer.verify();
    }

    @Test
    void testGetAccessTokenEmptyResponseBody() throws Exception {
      DefaultCernSecurityBlockingService freshSvc = new DefaultCernSecurityBlockingService(rtf, props);
      
      MockRestServiceServer mockServer = mockRtf.resetTemplate();
      
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withSuccess("",APPLICATION_JSON));
      
      Method getAccessToken = DefaultCernSecurityBlockingService.class
          .getDeclaredMethod("getAccessToken");
      getAccessToken.setAccessible(true);
      
      InvocationTargetException invocationException = 
          assertThrows(InvocationTargetException.class, () -> {
            getAccessToken.invoke(freshSvc);
          });
      
      assertTrue(invocationException.getCause() instanceof CernSecurityBlockingError);
      assertTrue(invocationException.getCause().getMessage().contains("empty body"));
      mockServer.verify();
    }

    @Test
    void testGetAccessTokenWithGracePeriod() throws Exception {
      CernProperties testProps = new CernProperties();
      CernProperties.CernBlockingProperties b = new CernProperties.CernBlockingProperties();
      b.setClientId("cid");
      b.setClientSecret("secret");
      b.setAudience("aud");
      b.setTokenUrl("https://token.url");
      b.setAuthorizationUrl("http://authorization.test.example");
      b.setGracePeriod(60);  
      testProps.setBlocking(b);
      
      DefaultCernSecurityBlockingService freshSvc = new DefaultCernSecurityBlockingService(rtf, testProps);
      
      MockRestServiceServer mockServer = mockRtf.resetTemplate();
      ObjectMapper om = new ObjectMapper();
      
      CernTokenResponse tokenResponse = new CernTokenResponse();
      Field at = CernTokenResponse.class.getDeclaredField("accessToken");
      at.setAccessible(true);
      at.set(tokenResponse, "token-with-grace");
      Field ei = CernTokenResponse.class.getDeclaredField("expiresIn");
      ei.setAccessible(true);
      ei.setLong(tokenResponse, 3600L);  
      
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withSuccess(om.writeValueAsString(tokenResponse),
              APPLICATION_JSON));
      
      Method getAccessToken = DefaultCernSecurityBlockingService.class
          .getDeclaredMethod("getAccessToken");
      getAccessToken.setAccessible(true);
      String token = (String) getAccessToken.invoke(freshSvc);
      
      assertEquals("token-with-grace", token);
      
      Field tokenExpiryField = DefaultCernSecurityBlockingService.class.getDeclaredField("tokenExpiry");
      tokenExpiryField.setAccessible(true);

      Instant expiry = (Instant) tokenExpiryField.get(freshSvc);
      Instant endTimeWithoutGrace = Instant.now().plusSeconds(3600L);
      Instant endTimeWithGrace = Instant.now().plusSeconds(3600L - 60L);
      

      assertTrue(expiry.isBefore(endTimeWithoutGrace));
      assertTrue(expiry.isAfter(endTimeWithGrace.minusSeconds(2)));
      
      mockServer.verify();
    }

    @Test
    void testGetAccessTokenError() throws Exception {
      DefaultCernSecurityBlockingService freshSvc = new DefaultCernSecurityBlockingService(rtf, props);
      
      MockRestServiceServer mockServer = mockRtf.resetTemplate();
      
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withException(
              new java.net.ConnectException("Connection refused")));
      
      Method getAccessToken = DefaultCernSecurityBlockingService.class.getDeclaredMethod("getAccessToken");
      getAccessToken.setAccessible(true);
      
      InvocationTargetException invocationException = 
          assertThrows(InvocationTargetException.class, () -> {
            getAccessToken.invoke(freshSvc);
          });
      
      assertTrue(invocationException.getCause() instanceof CernSecurityBlockingError);
      assertTrue(invocationException.getCause().getMessage().contains("Error fetching security blocking api access token"));
      mockServer.verify();
    }

    @Test
    void testGetAccessTokenServerError() throws Exception {
      DefaultCernSecurityBlockingService freshSvc = new DefaultCernSecurityBlockingService(rtf, props);
      
      MockRestServiceServer mockServer = mockRtf.resetTemplate();
      
      mockServer.expect(MockRestRequestMatchers.anything())
          .andRespond(MockRestResponseCreators.withStatus(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR));
      
      Method getAccessToken = DefaultCernSecurityBlockingService.class.getDeclaredMethod("getAccessToken");
      getAccessToken.setAccessible(true);
      
      InvocationTargetException invocationException = 
          assertThrows(InvocationTargetException.class, () -> {
            getAccessToken.invoke(freshSvc);
          });
      
      assertTrue(invocationException.getCause() instanceof CernSecurityBlockingError);
      assertTrue(invocationException.getCause().getMessage().contains("Error fetching security blocking api access token"));
      mockServer.verify();
    }
}