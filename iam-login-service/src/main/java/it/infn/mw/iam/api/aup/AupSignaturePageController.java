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
package it.infn.mw.iam.api.aup;

import static it.infn.mw.iam.core.web.aup.EnforceAupFilter.REQUESTING_SIGNATURE;
import static java.lang.String.format;
import static java.util.Objects.isNull;
import static java.util.Optional.ofNullable;

import java.util.Date;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.audit.events.aup.AupSignedEvent;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureUpdateError;

@Controller
public class AupSignaturePageController {


  final IamAupRepository repo;
  final IamAupSignatureRepository signatureRepo;
  final AccountUtils accountUtils;
  final TimeProvider timeProvider;
  final ApplicationEventPublisher publisher;

  public AupSignaturePageController(IamAupRepository aupRepo,
      IamAupSignatureRepository aupSignatureRepo, AccountUtils accountUtils,
      TimeProvider timeProvider, ApplicationEventPublisher publisher) {
    this.repo = aupRepo;
    this.signatureRepo = aupSignatureRepo;
    this.accountUtils = accountUtils;
    this.timeProvider = timeProvider;
    this.publisher = publisher;
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping(value = "/iam/aup/sign")
  public ModelAndView signAupPage() {
    ModelAndView view;

    Optional<IamAup> aup = repo.findDefaultAup();

    if (aup.isPresent()) {
      view = new ModelAndView("iam/signAup");
      view.addObject("aup", aup.get());
    } else {
      view = new ModelAndView("iam/noAup");
    }

    return view;
  }

  private Optional<SavedRequest> checkForSavedSpringSecurityRequest(HttpSession session) {
    SavedRequest savedRequest =
        (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");

    if (!isNull(savedRequest)) {
      session.removeAttribute("SPRING_SECURITY_SAVED_REQUEST");
    }

    return ofNullable(savedRequest);

  }


  @PreAuthorize("hasRole('USER')")
  @PostMapping(value = "/iam/aup/sign")
  public ModelAndView signAup(HttpServletRequest request, HttpServletResponse response,
      HttpSession session) throws IamAupSignatureUpdateError {

    Optional<IamAup> aup = repo.findDefaultAup();


    if (!aup.isPresent()) {
      return new ModelAndView("iam/noAup");
    }

    if (aup.isPresent()) {
      Date now = new Date(timeProvider.currentTimeMillis());
      IamAccount account = accountUtils.getAuthenticatedUserAccount().orElseThrow(
          () -> new IllegalStateException("No iam account found for authenticated user"));

      IamAupSignature signature = signatureRepo.createSignatureForAccount(aup.get(), account, now);

      publisher.publishEvent(new AupSignedEvent(this, signature));
      if (!isNull(session.getAttribute(REQUESTING_SIGNATURE))) {
        session.removeAttribute(REQUESTING_SIGNATURE);
        Optional<SavedRequest> savedRequest = checkForSavedSpringSecurityRequest(session);

        if (savedRequest.isPresent()) {
          return new ModelAndView(format("redirect:%s", savedRequest.get().getRedirectUrl()));
        }
      }
    }

    return new ModelAndView("redirect:/dashboard");
  }

  @ExceptionHandler(IamAupSignatureUpdateError.class)
  public ResponseEntity<ErrorDTO> aupSignatureUpdateError(Exception ex) {
    ErrorDTO errorResponse = ErrorDTO.fromString(ex.getMessage());
    return new ResponseEntity<>(errorResponse, HttpStatus.METHOD_NOT_ALLOWED);
  }
}


