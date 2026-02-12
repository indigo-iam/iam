package it.infn.mw.iam.test.lifecycle.cern;

import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.NO_PARTICIPATION_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.NO_PERSON_FOUND_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_MESSAGE;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_STATUS;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleUtils.LABEL_TIMESTAMP;
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
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
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import com.mercateo.test.clock.TestClock;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernSecurityBlockingApiService;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler;
import it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.AccountLifecycleStatus;
import it.infn.mw.iam.core.lifecycle.cern.CernSecurityBlockingHandler;
import it.infn.mw.iam.core.lifecycle.cern.CernStatus;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

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
    ExpiredAccountsHandler expiredAccountsHandler;

    @Autowired
    CernHrDBApiService hrDb;

    @Autowired
    Clock clock;

    IamAccount cernUser;

    @BeforeEach
    void init() {

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
    }

    @AfterEach
    void teardown() {
        reset(blockingService);
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
    }
}