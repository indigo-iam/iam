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
package it.infn.mw.iam.test.registration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class RegistrationUsernameTests extends TestSupport {
    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MockOAuth2Filter oauth2Filter;

    @Autowired
    private MockMvc mvc;

    @Before
    public void setup() {
        oauth2Filter.cleanupSecurityContext();
    }

    @After
    public void teardown() {
        oauth2Filter.cleanupSecurityContext();
    }

    private RegistrationRequestDto createRegistrationRequest(String username) {

        String email = username + "@example.org";
        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(username);
        request.setNotes("Some short notes...");
        request.setPassword("password");

        return request;
    }

    @Test
    public void validUsernames() throws Exception {
        final String[] validUsernames = {"bob", "b", "test$", "root", "test1234", "test_", "_test"};

        for (String u : validUsernames) {
            RegistrationRequestDto r = createRegistrationRequest(u);
            mvc.perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(r))).andExpect(status().isOk());
        }

    }

    @Test
    public void nonUnixUsernames() throws Exception {
        final String[] nonUnixUsernames = {"£$%^&*(", ".,", "-test", "1test", "test$$", "username@example.com", "username@domain",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

        for (String u : nonUnixUsernames) {
            RegistrationRequestDto r = createRegistrationRequest(u);
            mvc.perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(r))).andExpect(status().isBadRequest());
        }
    }


}
