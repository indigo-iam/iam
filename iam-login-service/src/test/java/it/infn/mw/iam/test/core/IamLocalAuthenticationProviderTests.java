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

package it.infn.mw.iam.test.core;

import static org.junit.Assert.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LocalAuthenticationProperties;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.IamLocalAuthenticationProvider;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@RunWith(MockitoJUnitRunner.class)
public class IamLocalAuthenticationProviderTests {

    @Mock
    IamProperties properties;
    @Mock
    UserDetailsService uds;
    @Mock
    PasswordEncoder passwordEncoder;
    @Mock
    IamAccountRepository accountRepo;
    @Mock
    IamTotpMfaRepository totpMfaRepository;
    @Mock
    LocalAuthenticationProperties localAuthn;

    IamLocalAuthenticationProvider iamLocalAuthenticationProvider;

    @Before
    public void setup() {
        when(properties.getLocalAuthn()).thenReturn(localAuthn);
        iamLocalAuthenticationProvider = spy(new IamLocalAuthenticationProvider(properties, uds, passwordEncoder,
                accountRepo, totpMfaRepository));
    }

    private IamAccount newAccount(String username) {
        IamAccount result = new IamAccount();
        result.setUserInfo(new IamUserInfo());
        result.setPassword("secret");
        result.setUsername(username);
        result.setUuid(UUID.randomUUID().toString());
        return result;
    }

    @Test
    public void testWhenPreAuthenticatedThenAuthenticateSetFalseToAuthenticated() {
        ExtendedAuthenticationToken token = new ExtendedAuthenticationToken("test-principal", "test-credentials");
        token.setPreAuthenticated(true);
        IamAccount account = newAccount("test-user");
        when(accountRepo.findByUsername(anyString())).thenReturn(Optional.of(account));

        IamTotpMfa iamTotpMfa = new IamTotpMfa();
        iamTotpMfa.setActive(true);
        when(totpMfaRepository.findByAccount(account)).thenReturn(Optional.of(iamTotpMfa));

        ExtendedAuthenticationToken newToken = (ExtendedAuthenticationToken) iamLocalAuthenticationProvider
                .authenticate(token);

        assertFalse(newToken.isAuthenticated());
        // Verify that super.authenticate was not called
        verify(iamLocalAuthenticationProvider, never()).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }
}
