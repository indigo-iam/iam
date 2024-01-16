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
package it.infn.mw.iam.persistence.model;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "iam_totp_processed_records")
public class IamTotpProcessedRecords implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "processed_secrets_count")
    private Long processedSecretsCount = 0L;

    @Column(name = "total_records_to_process")
    private Long totalRecordsToProcess = 0L;

    @Column(name = "revert_processed_records")
    private Long revertProcessedRecords = 0L;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Long getProcessedSecretsCount() {
        return processedSecretsCount;
    }

    public void setProcessedSecretsCount(Long processedSecretsCount) {
        this.processedSecretsCount = processedSecretsCount;
    }

    public Long getTotalRecordsToProcess() {
        return totalRecordsToProcess;
    }

    public void setTotalRecordsToProcess(Long totalRecordsToProcess) {
        this.totalRecordsToProcess = totalRecordsToProcess;
    }

    public Long getRevertProcessedRecords() {
        return revertProcessedRecords;
    }

    public void setRevertProcessedRecords(Long revertProcessedRecords) {
        this.revertProcessedRecords = revertProcessedRecords;
    }

    @Override
    public String toString() {
        return "IamTotpProcessedRecords [id=" + id + ", processedSecretsCount=" + processedSecretsCount
                + ", totalRecordsToProcess=" + totalRecordsToProcess + ", revertProcessedRecords="
                + revertProcessedRecords + "]";
    }
}
