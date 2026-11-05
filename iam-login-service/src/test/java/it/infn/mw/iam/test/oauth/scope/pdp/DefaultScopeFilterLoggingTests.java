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
package it.infn.mw.iam.test.oauth.scope.pdp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.DefaultScopeFilter;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopePolicyEngine;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
class DefaultScopeFilterLoggingTests {

  private static final String CLIENT_ID = "dashboard";

  private final IamProperties properties = new IamProperties();
  private final IamAccount account = mock(IamAccount.class);
  private final AccountUtils accounts = mock(AccountUtils.class);
  private final ScopePolicyEngine engine = mock(ScopePolicyEngine.class);
  private final DefaultScopeFilter filter =
      new DefaultScopeFilter(properties, accounts, engine, properties);

  private final Logger logger = (Logger) LoggerFactory.getLogger(DefaultScopeFilter.class);
  private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
  private Level previousLevel;

  @BeforeEach
  void setUp() {
    properties.getScopeAuthz().setEnabled(true);
    when(accounts.isAdmin(account)).thenReturn(true);

    previousLevel = logger.getLevel();
    logger.setLevel(Level.INFO);
    appender.start();
    logger.addAppender(appender);
  }

  @AfterEach
  void tearDown() {
    logger.detachAppender(appender);
    logger.setLevel(previousLevel);
    appender.stop();
  }

  @Test
  void logsOnlyRemovedScopesWhenFilteringSucceeds() {
    properties.getScopeAuthz().setEarlyFail(false);
    Set<String> requested = Set.of("scim:read", "profile", "email", "openid");
    when(engine.apply(requested, account, CLIENT_ID)).thenReturn(Set.of("openid"));

    assertEquals(Set.of("scim:read", "openid"), filter.filterScopes(requested, account, CLIENT_ID));

    assertRemovedScopesLogged(Set.of("profile", "email"));
  }

  @Test
  void logsRemovedScopesBeforeEarlyFailThrows() {
    properties.getScopeAuthz().setEarlyFail(true);
    Set<String> requested = Set.of("iam:admin.write", "profile");
    when(engine.apply(requested, account, CLIENT_ID)).thenReturn(Set.of());

    assertThrows(InvalidRequestException.class,
        () -> filter.filterScopes(requested, account, CLIENT_ID));

    assertRemovedScopesLogged(Set.of("profile"));
  }

  @Test
  void skipsLogAndEarlyFailWhenOnlyARestoredAdminScopeWasDenied() {
    properties.getScopeAuthz().setEarlyFail(true);
    Set<String> requested = Set.of("scim:write", "profile");
    when(engine.apply(requested, account, CLIENT_ID)).thenReturn(Set.of("profile"));

    assertEquals(requested, filter.filterScopes(requested, account, CLIENT_ID));
    assertTrue(appender.list.isEmpty());
  }

  private void assertRemovedScopesLogged(Set<String> expectedScopes) {
    assertEquals(1, appender.list.size());
    ILoggingEvent event = appender.list.get(0);
    assertEquals(Level.INFO, event.getLevel());
    assertEquals("Scope policy removed scopes {} for client {}", event.getMessage());
    assertEquals(expectedScopes, event.getArgumentArray()[0]);
    assertEquals(CLIENT_ID, event.getArgumentArray()[1]);
  }
}
