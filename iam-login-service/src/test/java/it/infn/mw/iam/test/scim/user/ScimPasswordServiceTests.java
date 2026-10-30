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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.exception.ScimValidationException;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.api.scim.updater.builders.Replacers;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.IamBCryptPasswordEncoder;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;

class ScimPasswordServiceTests {

  private final IamAccountService accounts = mock(IamAccountService.class);
  private final IamAccountRepository repository = mock(IamAccountRepository.class);
  private final UserConverter converter = mock(UserConverter.class);
  private final PasswordEncoder encoder = mock(PasswordEncoder.class);
  private final IamOAuthAccessTokenRepository accessTokens =
      mock(IamOAuthAccessTokenRepository.class);
  private final IamOAuthRefreshTokenRepository refreshTokens =
      mock(IamOAuthRefreshTokenRepository.class);

  private ScimUserProvisioning provisioning() {
    return new ScimUserProvisioning(Clock.systemUTC(), accounts, accessTokens, refreshTokens,
        repository, encoder, converter, null, null, null, null, null, null, null, null, Set.of(),
        null, null);
  }

  @Test
  void createRejectsOversizedPasswordBeforeConversionOrPersistence() {
    ScimUser user = ScimUser.builder().password("é".repeat(37)).build();

    ScimValidationException error =
        assertThrows(ScimValidationException.class, () -> provisioning().create(user));

    assertEquals(IamBCryptPasswordEncoder.PASSWORD_TOO_LONG_MESSAGE, error.getMessage());
    verifyNoInteractions(converter, accounts, repository, encoder, accessTokens, refreshTokens);
  }

  @Test
  void createAcceptsExactly72Utf8Bytes() {
    ScimUser user = ScimUser.builder().password("é".repeat(36)).build();
    IamAccount account = IamAccount.newAccount();
    when(converter.entityFromDto(user)).thenReturn(account);
    when(accounts.createAccount(account)).thenReturn(account);
    when(converter.dtoFromEntity(account)).thenReturn(user);

    assertSame(user, provisioning().create(user));

    verify(accounts).createAccount(account);
  }

  @Test
  void createAllowsAbsentPasswordForExternallyAuthenticatedUsers() {
    ScimUser user = ScimUser.builder().build();
    IamAccount account = IamAccount.newAccount();
    when(converter.entityFromDto(user)).thenReturn(account);
    when(accounts.createAccount(account)).thenReturn(account);
    when(converter.dtoFromEntity(account)).thenReturn(user);

    assertSame(user, provisioning().create(user));

    verify(accounts).createAccount(account);
  }

  @Test
  void replacementRejectsOversizedPasswordBeforeChangingCredentialsOrTokens() {
    IamAccount account = IamAccount.newAccount();
    account.setPassword("original-hash");
    Replacers replacers = new Replacers(Clock.systemUTC(), repository, accounts, encoder, account,
        accessTokens, refreshTokens, mock(UsernameValidator.class));

    ScimValidationException error =
        assertThrows(ScimValidationException.class, () -> replacers.password("é".repeat(37)));

    assertEquals(IamBCryptPasswordEncoder.PASSWORD_TOO_LONG_MESSAGE, error.getMessage());
    assertEquals("original-hash", account.getPassword());
    verifyNoInteractions(repository, accounts, encoder, accessTokens, refreshTokens);
  }
}
