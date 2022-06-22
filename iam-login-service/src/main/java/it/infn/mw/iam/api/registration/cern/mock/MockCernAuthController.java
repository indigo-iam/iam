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
package it.infn.mw.iam.api.registration.cern.mock;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

import java.time.Instant;
import java.util.Date;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;

import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.dto.InstituteDTO;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.util.test.OidcSecurityContextBuilder;

@Controller
@Service
@Profile({"mock"})
public class MockCernAuthController implements CernHrDBApiService {

  @Autowired
  CernProperties properties;

  @RequestMapping(method = GET, path = "/mock-cern-auth")
  public String mockCernAuthentication(HttpSession session) {

    OidcSecurityContextBuilder builder = new OidcSecurityContextBuilder();

    builder.claim(properties.getPersonIdClaim(), "987654321")
      .claim("email", "test@example.org")
      .name("Test", "User")
      .username("test")
      .subject("123456789")
      .issuer(properties.getSsoIssuer())
      .authorities(EXT_AUTHN_UNREGISTERED_USER_AUTH.getAuthority());

    SecurityContext context = builder.buildSecurityContext();
    SecurityContextHolder.clearContext();
    SecurityContextHolder.setContext(context);

    session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, context);

    return "redirect:/start-registration";
  }

  @Override
  public boolean hasValidExperimentParticipation(String personId) {
    return false;
  }

  @Override
  public VOPersonDTO getHrDbPersonRecord(String personId) {
    VOPersonDTO dto = new VOPersonDTO();
    dto.setFirstName("TEST");
    dto.setName("USER");
    dto.setEmail("test@hr.cern");
    dto.setId(987654321L);

    ParticipationDTO p = new ParticipationDTO();

    p.setExperiment("test");
    p.setStartDate(Date.from(Instant.parse("2020-01-01T00:00:00.00Z")));

    InstituteDTO i = new InstituteDTO();
    i.setId("000001");
    i.setName("INFN");
    i.setCountry("IT");
    i.setTown("Bologna");
    p.setInstitute(i);

    dto.getParticipations().add(p);
    return dto;
  }
}
