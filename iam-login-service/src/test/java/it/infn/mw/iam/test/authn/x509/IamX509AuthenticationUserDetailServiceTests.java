package it.infn.mw.iam.test.authn.x509;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationUserDetailService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.ext_authn.x509.X509TestSupport;

@RunWith(MockitoJUnitRunner.class)
public class IamX509AuthenticationUserDetailServiceTests extends X509TestSupport {

    @Mock
    IamAccountRepository accountRepository;
    @Mock
    IamTotpMfaRepository totpMfaRepository;
    @Mock
    InactiveAccountAuthenticationHander inactiveAccountHandler;

    IamX509AuthenticationUserDetailService iamX509AuthenticationUserDetailService;
    PreAuthenticatedAuthenticationToken token;

    @Before
    public void setup() {
        iamX509AuthenticationUserDetailService = new IamX509AuthenticationUserDetailService(accountRepository,
                totpMfaRepository, inactiveAccountHandler);
        token = new PreAuthenticatedAuthenticationToken("test-principal",
                "test-credentials");
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
    public void testIfMfaActiveThenRolePreAuthenticatedIsAdded() {

        IamAccount account = newAccount("test-user");
        when(accountRepository.findByCertificateSubject(anyString())).thenReturn(Optional.of(account));

        IamTotpMfa iamTotpMfa = new IamTotpMfa();
        iamTotpMfa.setActive(true);
        when(totpMfaRepository.findByAccount(account)).thenReturn(Optional.of(iamTotpMfa));

        UserDetails userDetails = iamX509AuthenticationUserDetailService.loadUserDetails(token);

        assertTrue(hasRole(userDetails, "ROLE_PRE_AUTHENTICATED"));
    }

    private boolean hasRole(UserDetails userDetails, String role) {
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role::equals);
    }
}
