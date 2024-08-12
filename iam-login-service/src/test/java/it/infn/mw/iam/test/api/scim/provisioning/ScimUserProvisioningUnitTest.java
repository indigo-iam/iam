package it.infn.mw.iam.test.api.scim.provisioning;

import static org.hamcrest.Matchers.anything;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.converter.OidcIdConverter;
import it.infn.mw.iam.api.scim.converter.SamlIdConverter;
import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;
import it.infn.mw.iam.test.api.TestSupport;

@RunWith(MockitoJUnitRunner.class)
public class ScimUserProvisioningUnitTest extends TestSupport {

    @Mock
    IamAccountService accountService;
    @Mock
    OAuth2TokenEntityService tokenService;
    @Mock
    IamAccountRepository accountRepository;
    @Mock
    PasswordEncoder passwordEncoder;
    @Mock
    UserConverter userConverter;
    @Mock
    OidcIdConverter oidcIdConverter;
    @Mock
    SamlIdConverter samlIdConverter;
    @Mock
    SshKeyConverter sshKeyConverter;
    @Mock
    X509CertificateConverter x509CertificateConverter;
    @Mock
    UsernameValidator usernameValidator;
    @Mock
    NotificationFactory notificationFactory;
    @Mock
    ApplicationEventPublisher eventPublisher;

    ScimUserProvisioning scimUserProvisioning;
    IamAccount testUser;

    @Before
    public void before() {
        testUser = new IamAccount();
        testUser.setUuid(TEST_USER_UUID);
        testUser.setServiceAccount(false);

        when(accountRepository.findByUuid(testUser.getUuid())).thenReturn(Optional.of(testUser));

        scimUserProvisioning = new ScimUserProvisioning(accountService, tokenService, accountRepository,
                passwordEncoder, userConverter, oidcIdConverter, samlIdConverter, sshKeyConverter,
                x509CertificateConverter, usernameValidator, notificationFactory);
        scimUserProvisioning.setApplicationEventPublisher(eventPublisher);
    }

    @Test
    public void testCreateSetAsServiceAccountMessageIsCalled() {
        List<ScimPatchOperation<ScimUser>> operations = getOperations(true);

        scimUserProvisioning.update(testUser.getUuid(), operations);

        verify(notificationFactory, times(1)).createSetAsServiceAccountMessage(testUser);
    }

    @Test
    public void testCreateRevokeServiceAccountMessageIsCalled() {
        testUser.setServiceAccount(true);
        List<ScimPatchOperation<ScimUser>> operations = getOperations(false);

        scimUserProvisioning.update(testUser.getUuid(), operations);

        verify(notificationFactory, times(1)).createRevokeServiceAccountMessage(testUser);
    }

    private List<ScimPatchOperation<ScimUser>> getOperations(boolean isServiceAccount) {
        ScimUser user = ScimUser.builder().serviceAccount(isServiceAccount).build();
        List<ScimPatchOperation<ScimUser>> operations = Lists.newArrayList();
        operations.add(new ScimPatchOperation.Builder<ScimUser>().replace().value(user).build());
        return operations;
    }
}
