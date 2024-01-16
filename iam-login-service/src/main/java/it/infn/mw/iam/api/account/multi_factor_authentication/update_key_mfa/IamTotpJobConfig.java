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
import org.springframework.batch.core.configuration.annotation.EnableBatchProcessing;
import org.springframework.batch.core.configuration.annotation.JobBuilderFactory;
import org.springframework.batch.core.configuration.annotation.StepBuilderFactory;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.core.listener.JobExecutionListenerSupport;
import org.springframework.batch.core.repository.JobExecutionAlreadyRunningException;
import org.springframework.batch.core.repository.JobInstanceAlreadyCompleteException;
import org.springframework.batch.core.repository.JobRestartException;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.batch.item.ItemReader;
import org.springframework.batch.item.ItemWriter;
import org.springframework.batch.item.database.JpaPagingItemReader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaEncryptionAndDecryptionService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamTotpProcessedRecords;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.persistence.repository.IamTotpProcessedRecordsRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import org.springframework.context.ApplicationContext;
import javax.annotation.PostConstruct;
import javax.persistence.EntityManagerFactory;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Configuration
@EnableBatchProcessing
public class IamTotpJobConfig extends JobExecutionListenerSupport {

    private final JobBuilderFactory jobBuilderFactory;
    private final StepBuilderFactory stepBuilderFactory;
    private final EntityManagerFactory entityManagerFactory;
    private final IamTotpMfaRepository iamTotpMfaRepository;
    private final IamTotpMfaProperties iamTotpMfaProperties;
    private final IamTotpMfaEncryptionAndDecryptionService iamTotpMfaEncryptionAndDecryptionService;
    private final IamTotpProcessedRecordsRepository iamTotpProcessedRecordsRepository;
    private Optional<IamTotpProcessedRecords> iamTotpProcessedRecords;
    private final ApplicationContext applicationContext;

    public IamTotpJobConfig(JobBuilderFactory jobBuilderFactory,
                                      StepBuilderFactory stepBuilderFactory,
                                      EntityManagerFactory entityManagerFactory,
                                      IamTotpMfaRepository iamTotpMfaRepository,
                                      IamTotpMfaProperties iamTotpMfaProperties,
                                      IamTotpMfaEncryptionAndDecryptionService iamTotpMfaEncryptionAndDecryptionService,
                                      IamTotpProcessedRecordsRepository iamTotpProcessedRecordsRepository,
                                      ApplicationContext applicationContext) {
        this.jobBuilderFactory = jobBuilderFactory;
        this.stepBuilderFactory = stepBuilderFactory;
        this.entityManagerFactory = entityManagerFactory;
        this.iamTotpMfaRepository = iamTotpMfaRepository;
        this.iamTotpMfaProperties = iamTotpMfaProperties;
        this.iamTotpMfaEncryptionAndDecryptionService = iamTotpMfaEncryptionAndDecryptionService;
        this.iamTotpProcessedRecordsRepository = iamTotpProcessedRecordsRepository;
        this.applicationContext = applicationContext;
    }

    @PostConstruct
    public void init() {
        iamTotpProcessedRecords = iamTotpProcessedRecordsRepository.findById(1);
    }

    @Bean
    public Step iamTotpPasswordsStep(ItemReader<IamTotpMfa> totpMfaReader,
                                    ItemProcessor<IamTotpMfa, IamTotpMfa> totpMfaProcessor,
                                    ItemWriter<IamTotpMfa> totpMfaWriter) {
        return stepBuilderFactory.get("iamTotpPasswordsStep")
                .<IamTotpMfa, IamTotpMfa>chunk(7)
                .reader(totpMfaReader())
                .processor(totpMfaProcessor())
                .writer(totpMfaWriter())
                .faultTolerant()
                .retryLimit(0)
                .build();
    }

    @Bean
    public Job iamTotpPasswordsJob(Step iamTotpPasswordsStep) {
        return jobBuilderFactory.get("iamTotpPasswordsJob")
                .listener(this)
                .start(iamTotpPasswordsStep)
                .build();
    }

    @Bean
    public Step iamTotpPasswordsRevertStep(ItemReader<IamTotpMfa> totpMfaReaderForRevertJob,
                                    ItemProcessor<IamTotpMfa, IamTotpMfa> totpMfaProcessorForRevertJob,
                                    ItemWriter<IamTotpMfa> tototpMfaWriterForRevertJob) {
        return stepBuilderFactory.get("iamTotpPasswordsRevertStep")
                .<IamTotpMfa, IamTotpMfa>chunk(30)
                .reader(totpMfaReaderForRevertJob())
                .processor(totpMfaProcessorForRevertJob())
                .writer(tototpMfaWriterForRevertJob())
                .faultTolerant()
                .retryLimit(3)
                .retry(Exception.class)
                .build();
    }

    @Bean
    public Job iamTotpPasswordsRevertJob(Step iamTotpPasswordsRevertStep) {
        return jobBuilderFactory.get("iamTotpPasswordsRevertJob")
                .listener(this)
                .start(iamTotpPasswordsRevertStep)
                .build();
    }
    
    @Bean
    public ItemReader<IamTotpMfa> totpMfaReader() {
        JpaPagingItemReader<IamTotpMfa> reader = new JpaPagingItemReader<>();
        IamTotpProcessedRecords iamTotpProcessedRecord = iamTotpProcessedRecords.get();

        reader.setQueryString("SELECT t FROM IamTotpMfa t WHERE t.id >= :startFrom AND t.id <= :totalRecordsToProcess");
        reader.setParameterValues(Map.of(
            "startFrom", iamTotpProcessedRecord.getProcessedSecretsCount(),
            "totalRecordsToProcess", iamTotpMfaEncryptionAndDecryptionService.getTotalRecordsToProcess()));
        reader.setEntityManagerFactory(entityManagerFactory);
        reader.setPageSize(7);

        return reader;
    }

    @Bean
    public ItemProcessor<IamTotpMfa, IamTotpMfa> totpMfaProcessor() {
        return item -> {
            if (!item.isKeyUpdateRequest()) {
                String plainText = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(item.getSecret(),
                        iamTotpMfaProperties.getOldPasswordToEncryptAndDecrypt());

                item.setSecret(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(plainText,
                        iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
                item.setKeyUpdateRequest(true);

                Set<IamTotpRecoveryCode> accountRecoveryCodes = item.getRecoveryCodes();

                for (IamTotpRecoveryCode recoveryCodeObject : accountRecoveryCodes) {
                    String recoveryCodeEncrypted = recoveryCodeObject.getCode();

                    String recoveryCodeString = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(
                            recoveryCodeEncrypted, iamTotpMfaProperties.getOldPasswordToEncryptAndDecrypt());

                    recoveryCodeObject.setCode(IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(
                            recoveryCodeString, iamTotpMfaProperties.getPasswordToEncryptOrDecrypt()));
                    recoveryCodeObject.setKeyUpdateRequest(true);
                }
            }

            return item;
        };
    }

    @Bean
    public ItemWriter<IamTotpMfa> totpMfaWriter() {
        return items -> {
            iamTotpMfaRepository.saveAll(items);
            iamTotpMfaEncryptionAndDecryptionService.incrementRecordsProcessedBy(items.size());
            IamTotpProcessedRecords iamTotpProcessedRecord = iamTotpProcessedRecords.get();
            iamTotpProcessedRecord.setProcessedSecretsCount(iamTotpMfaEncryptionAndDecryptionService.getRecordsProcessed());
            iamTotpProcessedRecordsRepository.save(iamTotpProcessedRecord);
        };
    }

    @Bean
    public ItemReader<IamTotpMfa> totpMfaReaderForRevertJob() {
        JpaPagingItemReader<IamTotpMfa> reader = new JpaPagingItemReader<>();
        IamTotpProcessedRecords iamTotpProcessedRecord = iamTotpProcessedRecords.get();
        reader.setQueryString("SELECT t FROM IamTotpMfa t WHERE t.id >= :startFrom AND t.id <= :totalRecordsToProcess");
        reader.setParameterValues(Map.of(
            "startFrom", iamTotpProcessedRecord.getRevertProcessedRecords(),
            "totalRecordsToProcess", iamTotpMfaEncryptionAndDecryptionService.getTotalRecordsToProcess()));
        reader.setEntityManagerFactory(entityManagerFactory);
        reader.setPageSize(30);
        return reader;
    }

    @Bean
    public ItemProcessor<IamTotpMfa, IamTotpMfa> totpMfaProcessorForRevertJob() {
        return item -> {
                item.setKeyUpdateRequest(false);
                Set<IamTotpRecoveryCode> accountRecoveryCodes = item.getRecoveryCodes();

                for (IamTotpRecoveryCode recoveryCodeObject : accountRecoveryCodes) {
                    recoveryCodeObject.setKeyUpdateRequest(false);
                }

            return item;
        };
    }

    @Bean
    public ItemWriter<IamTotpMfa> tototpMfaWriterForRevertJob() {
        return items -> {
            iamTotpMfaEncryptionAndDecryptionService.incrementRevertRecordsProcessedCount(items.size());

            iamTotpMfaRepository.saveAll(items);
            IamTotpProcessedRecords iamTotpProcessedRecord = iamTotpProcessedRecords.get();
            iamTotpProcessedRecord.setRevertProcessedRecords(iamTotpMfaEncryptionAndDecryptionService.getRevertRecordsProcessedCount());
            iamTotpProcessedRecordsRepository.save(iamTotpProcessedRecord);
        };
    }

    @Override
    public void afterJob(JobExecution jobExecution) {
        String jobName = jobExecution.getJobInstance().getJobName();
        String exitCode = jobExecution.getExitStatus().getExitCode();

        if ("iamTotpPasswordsRevertJob".equalsIgnoreCase(jobName)) {
            IamTotpProcessedRecords iamTotpProcessedRecord = iamTotpProcessedRecords.get();

            if (exitCode.equals(ExitStatus.COMPLETED.getExitCode())) {
                iamTotpMfaEncryptionAndDecryptionService.setTriggerIamTotpPasswordsJobSuccessful(true);

                iamTotpProcessedRecord.setProcessedSecretsCount(0L);
                iamTotpProcessedRecord.setTotalRecordsToProcess(0L);
                iamTotpProcessedRecord.setRevertProcessedRecords(0L);
                iamTotpProcessedRecordsRepository.save(iamTotpProcessedRecord);
            }
        } else {
            if (exitCode.equals(ExitStatus.COMPLETED.getExitCode())) {
                triggerSecondJob();
            }
        }

        iamTotpMfaEncryptionAndDecryptionService.setCheckIfadminTriggeredTheJob(false);
    }

    private void triggerSecondJob() {
        try {
            JobLauncher jobLauncher = applicationContext.getBean(JobLauncher.class);
            Job iamTotpPasswordsRevertJob = applicationContext.getBean("iamTotpPasswordsRevertJob", Job.class);
            jobLauncher.run(iamTotpPasswordsRevertJob, new JobParameters());
        } catch (JobExecutionAlreadyRunningException | JobRestartException | JobInstanceAlreadyCompleteException
                | JobParametersInvalidException e) {
            e.printStackTrace();
        }
    }
}
