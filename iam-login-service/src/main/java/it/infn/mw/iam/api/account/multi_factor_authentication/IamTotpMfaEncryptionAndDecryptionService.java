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
package it.infn.mw.iam.api.account.multi_factor_authentication;

import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.PostConstruct;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamTotpProcessedRecords;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.persistence.repository.IamTotpProcessedRecordsRepository;

@Service
public class IamTotpMfaEncryptionAndDecryptionService {

    private volatile boolean triggerIamTotpPasswordsJobsuccessful = false;
    private final AtomicLong recordsProcessed = new AtomicLong(0);
    private final AtomicLong revertRecordsProcessedCount = new AtomicLong(0);

    private Long totalRecordsToProcess = 0L;
    private final IamTotpMfaProperties iamTotpMfaProperties;
    private final IamTotpMfaRepository iamtotpMfaRepository;
    private final IamTotpProcessedRecordsRepository iamTotpProcessedRecordsRepository;

    private volatile boolean checkIfadminTriggeredTheJob = false;

    public IamTotpMfaEncryptionAndDecryptionService(
        IamTotpMfaProperties iamTotpMfaProperties,
        IamTotpMfaRepository iamTotpMfaRepository,
        IamTotpProcessedRecordsRepository iamTotpProcessedRecordsRepository) {
        this.iamTotpMfaProperties = iamTotpMfaProperties;
        this.iamTotpProcessedRecordsRepository = iamTotpProcessedRecordsRepository;
        this.iamtotpMfaRepository = iamTotpMfaRepository;
    }

    public boolean hasTriggerIamTotpPasswordsJobSuccessful() {
        return triggerIamTotpPasswordsJobsuccessful;
    }

    public void setTriggerIamTotpPasswordsJobSuccessful(boolean triggerIamTotpPasswordsJobsuccessful) {
        this.triggerIamTotpPasswordsJobsuccessful = triggerIamTotpPasswordsJobsuccessful;
    }

    public long getRecordsProcessed() {
        return recordsProcessed.get();
    }

    public void incrementRecordsProcessedBy(long increment) {
        recordsProcessed.addAndGet(increment);
    }

    public long getRevertRecordsProcessedCount() {
        return revertRecordsProcessedCount.get();
    }

    public void incrementRevertRecordsProcessedCount(long increment) {
        revertRecordsProcessedCount.addAndGet(increment);
    }

    public Long getTotalRecordsToProcess() {
        return totalRecordsToProcess;
    }

    public void setTotalRecordsToProcess(Long totalRecordsToProcess) {
        this.totalRecordsToProcess = totalRecordsToProcess;
    }

    public boolean hasAdminTriggeredTheJob() {
        return checkIfadminTriggeredTheJob;
    }

    public void setCheckIfadminTriggeredTheJob(boolean adminTriggeredTheJob) {
        this.checkIfadminTriggeredTheJob = adminTriggeredTheJob;
    }

    public String whichPasswordToUseForEncryptAndDecrypt(long currentIDOfIamTotpMfaSecret, boolean alreadyUpdated) {
        if (alreadyUpdated) {
            return iamTotpMfaProperties.getPasswordToEncryptOrDecrypt();
        } else {
            if (currentIDOfIamTotpMfaSecret > totalRecordsToProcess || hasTriggerIamTotpPasswordsJobSuccessful()) {
                return iamTotpMfaProperties.getPasswordToEncryptOrDecrypt();
            }

            return iamTotpMfaProperties.getOldPasswordToEncryptAndDecrypt();
        }
    }

    public boolean hasAdminRequestedToUpdateTheKey() {
        return iamTotpMfaProperties.isUpdateKeyRequest()
                && iamTotpMfaProperties.getOldPasswordToEncryptAndDecrypt().length() > 0;
    }

    public String getOldPasswordFromService() {
        return iamTotpMfaProperties.getOldPasswordToEncryptAndDecrypt();       
    }

    public String getCurrentPasswordFromService() {
        return iamTotpMfaProperties.getPasswordToEncryptOrDecrypt();       
    }

    @PostConstruct
    public void initialize() {
        if (hasAdminRequestedToUpdateTheKey()) {
            setTotalRecordsToProcess(iamtotpMfaRepository.count());

            IamTotpProcessedRecords iamTotpProcessedRecords = new IamTotpProcessedRecords();
            iamTotpProcessedRecords.setTotalRecordsToProcess(getTotalRecordsToProcess());
            iamTotpProcessedRecordsRepository.save(iamTotpProcessedRecords);
        }
    }
}
