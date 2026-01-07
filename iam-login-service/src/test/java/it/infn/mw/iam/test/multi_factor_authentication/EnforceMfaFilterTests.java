package it.infn.mw.iam.test.multi_factor_authentication;

import static it.infn.mw.iam.core.web.multi_factor_authentication.EnforceMfaFilter.ACTIVATE_MFA_PATH;
import static it.infn.mw.iam.core.web.multi_factor_authentication.EnforceMfaFilter.REQUESTING_MFA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = { IamLoginService.class }, webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = "mfa.multi-factor-mandatory=true")
public class EnforceMfaFilterTests {

    @Autowired
    private MockMvc mvc;

    @Test
    @WithMockUser(username = "test", roles = "USER")
    public void testWhenPathAllowedThenNoRedirection() throws Exception {
        mvc.perform(get(ACTIVATE_MFA_PATH)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @WithAnonymousUser
    public void testWhenNotAuthenticatedThenNoRedirection() throws Exception {
        mvc.perform(get("/dashboard")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isFound());
    }

    @Test
    @WithMockUser(username = "Unknown", roles = "USER")
    public void testWhenNoAuthenticatedUserFoundThenNoRedirection() throws Exception {
        mvc.perform(get("/dashboard")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "test", roles = "USER")
    public void testWhenRequestingMfaThenRedirection() throws Exception {

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
    public void testWhenAuthenticatorAppNotActiveThenRedirection() throws Exception {

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

    @Nested
    @IamMockMvcIntegrationTest
    @SpringBootTest(classes = { IamLoginService.class }, webEnvironment = WebEnvironment.MOCK)
    @TestPropertySource(properties = "mfa.multi-factor-mandatory=false")
    class EnforceMfaFilterMfaNotMandatoryTests {
        @Autowired
        private MockMvc mvc;

        @Test
        @WithMockUser(username = "test", roles = "USER")
        public void testWhenMultiFactorIsNotMandatoryThenNoRedirection() throws Exception {
            mvc.perform(get("/dashboard")
                    .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());
        }
    }
}
