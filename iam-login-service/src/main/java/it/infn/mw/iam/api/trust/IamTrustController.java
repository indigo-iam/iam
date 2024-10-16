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
package it.infn.mw.iam.api.trust;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.trust.sevice.IamTrustService;



@RestController
@RequestMapping("/iam/api/trusts")
public class IamTrustController {

    @Autowired
    IamTrustService trustService;

    @GetMapping
    public ListResponseDTO<String> getTrusts() throws NoSuchAlgorithmException, KeyStoreException {
        return trustService.getTrusts();
    }

    @ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler({NoSuchAlgorithmException.class, KeyStoreException.class})
    public ErrorDTO constraintValidationError(HttpServletRequest req, Exception ex) {
        return ErrorDTO.fromString("Could not get trust store");
    }
}
