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
package it.infn.mw.iam.test.scim.converter;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.api.account.group_manager.AccountGroupManagerService;
import it.infn.mw.iam.api.scim.converter.AddressConverter;
import it.infn.mw.iam.api.scim.converter.OidcIdConverter;
import it.infn.mw.iam.api.scim.converter.SamlIdConverter;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.config.scim.ScimProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@RunWith(MockitoJUnitRunner.class)
public class UserConverterTest {

    @Mock
    private ScimResourceLocationProvider resourceLocationProvider;
    @Mock
    private AddressConverter addressConverter;
    @Mock
    private OidcIdConverter oidcIdConverter;
    @Mock
    private SshKeyConverter sshKeyConverter;
    @Mock
    private SamlIdConverter samlIdConverter;
    @Mock
    private X509CertificateConverter x509CertificateIamConverter;
    @Mock
    private AccountGroupManagerService groupManagerService;
    @Mock
    private ScimProperties properties;

    private UserConverter userConverter;
    
    @Before
    public void setup() {
        when(resourceLocationProvider.userLocation(anyString())).thenReturn("User location");

        userConverter = new UserConverter(properties, resourceLocationProvider, addressConverter,
                            oidcIdConverter, sshKeyConverter, samlIdConverter, x509CertificateIamConverter, groupManagerService);        
    }

    @Test
    public void testEntityWithAffiliationProduceDtoWithAffiliation() {
        IamUserInfo userInfo = new IamUserInfo();
        userInfo.setAffiliation("Test user affiliation");

        IamAccount iamAccount = new IamAccount();
        iamAccount.setUsername("Test User");
        iamAccount.setUuid("UUID");
        iamAccount.setUserInfo(userInfo);

        ScimUser scimUser = userConverter.dtoFromEntity(iamAccount);

        assertEquals("Test user affiliation", scimUser.getIndigoUser().getAffiliation());
    }

    @Test
    public void testDtoWithAffiliationProduceEntityWithAffiliation() {
        ScimUser.Builder userBuilder = ScimUser.builder()
                                        .buildName("Test Givenname", "Test Familyname")
                                        .buildEmail("test@example.com")
                                        .userName("Test Username")
                                        .affiliation("Test user affiliation");

        IamAccount iamAccount = userConverter.entityFromDto(userBuilder.build());

        assertEquals("Test user affiliation", iamAccount.getUserInfo().getAffiliation());
    }
}
