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
package it.infn.mw.iam.test.multi_factor_authentication;

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_ACTIVATE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.REQUESTING_MFA;
import static it.infn.mw.iam.core.web.aup.EnforceAupFilter.AUP_SIGN_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.test.util.WithAnonymousUser;

@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@SpringBootTest(classes = { IamLoginService.class }, webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = { "mfa.multi-factor-mandatory=true",
        "logging.level.root=DEBUG",
        "logging.level.it.infn.mw.iam.core.web.multi_factor_authentication.EnforceMfaFilter=DEBUG"
})
class EnforceMfaFilterTests {
    @Autowired
    private IamTotpMfaProperties iamTotpMfaProperties;

    @Autowired
    private MockMvc mvc;

    @Test
    @WithMockUser(username = "test", roles = "USER")
    void testMfaActivateUrlNotAccessableWithUserRole() throws Exception {
        mvc.perform(get(MFA_ACTIVATE_URL)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "test", roles = "PRE_AUTHENTICATED")
    void testWhenPathAllowedThenNoRedirection() throws Exception {
        mvc.perform(get(MFA_ACTIVATE_URL)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "test", roles = "USER")
    void testWhenAupPathAllowedThenNoRedirection() throws Exception {
        mvc.perform(get(AUP_SIGN_PATH)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "test", roles = "USER")
    void testWhenPrefixAllowedThenNoRedirection() throws Exception {
        mvc.perform(get("/login")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isFound());
    }

    @Test
    @WithAnonymousUser
    void testWhenNotAuthenticatedThenNoRedirection() throws Exception {
        mvc.perform(get("/dashboard")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isFound());
    }

    @Test
    @WithMockUser(username = "Unknown", roles = "USER")
    void testWhenNoAuthenticatedUserFoundThenNoRedirection() throws Exception {
        mvc.perform(get("/dashboard")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "test", roles = "USER")
    void testWhenRequestingMfaThenRedirection() throws Exception {

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(REQUESTING_MFA, Boolean.TRUE);

        mvc.perform(get("/dashboard")
                .session(session)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/iam/mfa/activate"))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    @WithMockUser(username = "test", roles = "USER")
    void testWhenAuthenticatorAppNotActiveThenRedirection() throws Exception {

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(REQUESTING_MFA, Boolean.FALSE);

        MvcResult result = mvc.perform(get("/dashboard")
                .session(session)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/iam/mfa/activate"))
                .andReturn();

        HttpSession postSession = result.getRequest().getSession(false);
        assertThat(postSession).isNotNull();
        assertThat(postSession.getAttribute(REQUESTING_MFA)).isEqualTo(Boolean.TRUE);

    }

    @Test
    @WithMockUser(username = "test", roles = "USER")
    void testWhenMultiFactorIsNotMandatoryThenNoRedirection() throws Exception {
        iamTotpMfaProperties.setMultiFactorMandatory(false);

        mvc.perform(get("/dashboard")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        iamTotpMfaProperties.setMultiFactorMandatory(true);
    }
}
