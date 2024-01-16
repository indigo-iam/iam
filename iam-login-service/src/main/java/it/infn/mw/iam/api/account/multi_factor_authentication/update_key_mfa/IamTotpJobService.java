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

import org.springframework.batch.core.*;
import org.springframework.batch.core.explore.JobExplorer;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.IamTotpProcessedRecords;
import it.infn.mw.iam.persistence.repository.IamTotpProcessedRecordsRepository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

@Service
public class IamTotpJobService {

    private final JobLauncher jobLauncher;
    private final Job iamTotpPasswordsJob;
    private final Job iamTotpPasswordsRevertJob;
    private final JobExplorer jobExplorer;
    private final IamTotpProcessedRecordsRepository iamTotpProcessedRecordsRepository;
    private Optional<IamTotpProcessedRecords> iamTotpProcessedRecords;

    @Autowired
    public IamTotpJobService(JobLauncher jobLauncher, Job iamTotpPasswordsJob, JobExplorer jobExplorer, Job iamTotpPasswordsRevertJob, IamTotpProcessedRecordsRepository iamTotpProcessedRecordsRepository) {
        this.jobLauncher = jobLauncher;
        this.iamTotpPasswordsJob = iamTotpPasswordsJob;
        this.iamTotpPasswordsRevertJob = iamTotpPasswordsRevertJob;
        this.jobExplorer = jobExplorer;
        this.iamTotpProcessedRecordsRepository = iamTotpProcessedRecordsRepository;
    }

    @PostConstruct
    public void init() {
        iamTotpProcessedRecords = iamTotpProcessedRecordsRepository.findById(1);
    }

    @Async
    public void triggerIamTotpPasswordsJobAsync() {
        try {
            Long lastWriteCount = getLastWriteCount("iamTotpPasswordsJob");

            JobParameters jobParameters = new JobParametersBuilder()
                    .addLong("writeCount", lastWriteCount)
                    .toJobParameters();

            jobLauncher.run(iamTotpPasswordsJob, jobParameters);
        } catch (Exception e) {}
    }

    
    @Async
    public void triggerRevertJobAsync() {
        try {
            Long lastWriteCount = getLastWriteCountForRevertJob("iamTotpPasswordsRevertJob");

            JobParameters jobParameters = new JobParametersBuilder()
                    .addLong("writeCountForRevertJob", lastWriteCount)
                    .toJobParameters();

            jobLauncher.run(iamTotpPasswordsRevertJob, jobParameters);
        } catch (Exception e) {}
    }

    public String checkJobStatus() {
        try {
            // Need to check for the two Jobs.
            List<JobExecution> jobExecutions = jobExplorer.getJobInstances(iamTotpPasswordsJob.getName(), 0, 1)
                    .stream()
                    .map(jobInstance -> jobExplorer.getJobExecutions(jobInstance).get(0))
                    .collect(Collectors.toList());

            if (!jobExecutions.isEmpty()) {
                List<JobExecution> completedExecutions = jobExecutions.stream()
                        .filter(execution -> execution.getStatus() == BatchStatus.COMPLETED)
                        .collect(Collectors.toList());

                if (!completedExecutions.isEmpty()) {
                    return "Batch Job has completed successfully.";
                } else {
                    return "Batch Job is still running or has not been executed.";
                }
            } else {
                if (iamTotpProcessedRecords.isPresent()) {
                    IamTotpProcessedRecords iamTotpProcessedRecord = iamTotpProcessedRecords.get();
                    StringBuilder message = new StringBuilder();

                    if (iamTotpProcessedRecord.getProcessedSecretsCount() != 0) {
                        message.append("triggerIamTotpPasswordsJob batch has not been executed or triggered properly.");
                    } 
                    if (iamTotpProcessedRecord.getRevertProcessedRecords() != 0) {
                       message.append(" retryTriggerIamTotpPasswordsJob batch as it is not been executed or triggered properly.");
                    }
                    if (message.toString().length() > 0) {
                        return message.toString();
                    }
                }

                return "No Batch Job executions found.";
            }
        } catch (Exception e) {
            return "Error checking Batch Job status: " + e.getMessage();
        }
    }

    public Long getLastWriteCount(String jobName) {
        JobExecution lastJobExecution = findLastJobExecution(jobName);

        if (lastJobExecution != null) {
            ExecutionContext jobExecutionContext = lastJobExecution.getExecutionContext();
            return jobExecutionContext.getLong("writeCount", 0L);
        }

        return 0L;
    }

    public Long getLastWriteCountForRevertJob(String jobName) {
        JobExecution lastJobExecution = findLastJobExecution(jobName);

        if (lastJobExecution != null) {
            ExecutionContext jobExecutionContext = lastJobExecution.getExecutionContext();
            return jobExecutionContext.getLong("writeCountForRevertJob", 0L);
        }

        return 0L;
    }

    private JobExecution findLastJobExecution(String jobName) {
        JobInstance lastJobInstance = jobExplorer.getJobInstances(jobName, 0, 1).stream()
                .findFirst()
                .orElse(null);

        if (lastJobInstance != null) {
            return jobExplorer.getJobExecutions(lastJobInstance).stream()
                    .filter(jobExecution -> jobExecution.getStatus() == BatchStatus.COMPLETED)
                    .findFirst()
                    .orElse(null);
        }

        return null;
    }
}
