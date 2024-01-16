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
package it.infn.mw.iam.api.account.multi_factor_authentication.update_key_mfa;

import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaEncryptionAndDecryptionService;

@RestController
@RequestMapping("/batch")
@EnableAsync
@EnableScheduling
public class IamTotpJobController {

    private final IamTotpJobService batchJobService;
    private final IamTotpMfaEncryptionAndDecryptionService iamTotpMfaEncryptionAndDecryptionService;

    public IamTotpJobController(
            IamTotpJobService batchJobService,
            IamTotpMfaEncryptionAndDecryptionService iamTotpMfaEncryptionAndDecryptionService) {
        this.batchJobService = batchJobService;
        this.iamTotpMfaEncryptionAndDecryptionService = iamTotpMfaEncryptionAndDecryptionService;
    }

    // Need access to the ADMIN ONLY
    // @PreAuthorize("hasRole('ADMIN') or #iam.hasDashboardRole('ROLE_ADMIN')")
    @GetMapping("/triggerIamTotpPasswordsJob")
    public ResponseEntity<IamTotpJobControllerDTO> triggerIamTotpPasswordsJob(
            @RequestParam(name = "updateKeyRequestParam", defaultValue = "false") boolean updateKeyRequestParam) {
        try {
            if (updateKeyRequestParam) {
                if (iamTotpMfaEncryptionAndDecryptionService.hasAdminRequestedToUpdateTheKey()) {
                    iamTotpMfaEncryptionAndDecryptionService.setCheckIfadminTriggeredTheJob(true);

                    batchJobService.triggerIamTotpPasswordsJobAsync();

                    IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                            "Batch Job trigger initiated. Check status using /checkIamTotpPasswordsJobStatus endpoint.");

                    return ResponseEntity.ok(response);
                }
                IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                        "Please contact the technical support IAM ADMIN team");

                return ResponseEntity.ok(response);
            } else {
                IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                        "updateKeyRequestParam=true is not specified in the params to trigger the job");

                return ResponseEntity.ok(response);
            }
        } catch (Exception e) {
            IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                    "Error initiating the Batch Job: " + e.getMessage());

            return ResponseEntity.status(500).body(response);
        }
    }

    @GetMapping("/checkIamTotpPasswordsJobStatus")
    public ResponseEntity<IamTotpJobControllerDTO> checkJobStatus() {
        try {
            if (iamTotpMfaEncryptionAndDecryptionService.hasAdminRequestedToUpdateTheKey()) {

                String status = batchJobService.checkJobStatus();

                IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(status);
                return ResponseEntity.ok(response);
            } else {
                IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                        "Please contact the technical support IAM ADMIN team");

                return ResponseEntity.ok(response);
            }
        } catch (Exception e) {
            IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                    "Error checking Batch Job status: " + e.getMessage());

            return ResponseEntity.status(500).body(response);
        }
    }

    @GetMapping("/retryTriggerIamTotpPasswordsJob")
    public ResponseEntity<IamTotpJobControllerDTO> iamTotpPasswordsRevertJob() {
        try {
            if (iamTotpMfaEncryptionAndDecryptionService.hasAdminRequestedToUpdateTheKey()) {
                iamTotpMfaEncryptionAndDecryptionService.setCheckIfadminTriggeredTheJob(true);

                batchJobService.triggerRevertJobAsync();

                IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                        "Retrying batch Job trigger. Check status using /checkIamTotpPasswordsJobStatus endpoint.");

                return ResponseEntity.ok(response);
            }

            IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                    "Please contact the technical support IAM ADMIN team");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            IamTotpJobControllerDTO response = new IamTotpJobControllerDTO(
                    "Error initiating the Batch Job: " + e.getMessage());

            return ResponseEntity.status(500).body(response);
        }
    }
}
