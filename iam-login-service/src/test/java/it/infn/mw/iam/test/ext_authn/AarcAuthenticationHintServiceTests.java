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
package it.infn.mw.iam.test.ext_authn;

import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.when;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.authn.DefaultAARCHintService;
import it.infn.mw.iam.authn.error.InvalidAARCHintError;
import it.infn.mw.iam.authn.saml.DefaultMetadataLookupService;
import it.infn.mw.iam.authn.saml.model.IdpDescription;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcValidatedProviders;

@RunWith(MockitoJUnitRunner.class)
public class AarcAuthenticationHintServiceTests {

    private static final String BASE_URL = "http://localhost:8080";
    private static final String OIDC_ISSUER = "https://accounts.google.com";
    private static final String SAML_ENTITYID = "urn:example.us.auth0.com";

    @Mock
    private OidcValidatedProviders oidcProviders;

    @InjectMocks
    private DefaultAARCHintService service = new DefaultAARCHintService(BASE_URL, oidcProviders);

    @Mock
    private DefaultMetadataLookupService samlProviders;


    @Before
    public void setUp() {

        // Populating known Oidc's
        OidcProvider oidcProvider = new OidcProvider();
        oidcProvider.setIssuer(OIDC_ISSUER);
        List<OidcProvider> oidcProvidersTemp = List.of(oidcProvider);

        when(oidcProviders.getValidatedProviders()).thenReturn(oidcProvidersTemp);

        // Populating known Saml's
        IdpDescription idpDescription = new IdpDescription();
        idpDescription.setEntityId(SAML_ENTITYID);
        List<IdpDescription> idpDescriptionsTemp = List.of(idpDescription);

        when(samlProviders.listIdps()).thenReturn(idpDescriptionsTemp);
    }


    @Test(expected = InvalidAARCHintError.class)
    public void testNullAarcHint() {
        service.resolve(null);
    }

    @Test(expected = InvalidAARCHintError.class)
    public void testEmptyAarcHint() {
        service.resolve("");
    }

    @Test(expected = InvalidAARCHintError.class)
    public void testSpacesAarcHint() {
        service.resolve("   ");
    }


    @Test(expected = InvalidAARCHintError.class)
    public void testInvalidSchemeHint() {
        service.resolve("whatever:sdsdad");
    }

    @Test
    public void testSamlWorks() {
        String url = service.resolve(SAML_ENTITYID);
        assertThat(url, is(String.format("%s/saml/login?idp=%s", BASE_URL, SAML_ENTITYID)));
    }

    @Test
    public void testOidcWorks() {
        String url = service.resolve(OIDC_ISSUER);
        assertThat(url, is(String.format("%s/openid_connect_login?iss=%s", BASE_URL, OIDC_ISSUER)));
    }

}
