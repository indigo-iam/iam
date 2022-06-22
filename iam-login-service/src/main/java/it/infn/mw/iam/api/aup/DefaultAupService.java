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

import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.aup.error.AupNotFoundError;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.audit.events.aup.AupCreatedEvent;
import it.infn.mw.iam.audit.events.aup.AupDeletedEvent;
import it.infn.mw.iam.audit.events.aup.AupUpdatedEvent;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;

@Service
public class DefaultAupService implements AupService {

  private final IamAupRepository repo;
  private final IamAupSignatureRepository signatureRepo;
  private final AupConverter converter;

  private final TimeProvider timeProvider;
  private final ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultAupService(IamAupRepository repo, IamAupSignatureRepository signatureRepo,
      AupConverter converter, TimeProvider timeProvider, ApplicationEventPublisher eventPublisher) {
    this.repo = repo;
    this.signatureRepo = signatureRepo;
    this.converter = converter;
    this.timeProvider = timeProvider;
    this.eventPublisher = eventPublisher;
  }

  @Override
  public Optional<IamAup> findAup() {
    return repo.findDefaultAup();
  }

  @Override
  public IamAup saveAup(AupDTO aupDto) {
    IamAup aup = converter.entityFromDto(aupDto);
    long currentTimeMillis = timeProvider.currentTimeMillis();

    Date now = new Date(currentTimeMillis);
    aup.setCreationTime(now);
    aup.setLastUpdateTime(now);

    repo.saveDefaultAup(aup);

    eventPublisher.publishEvent(new AupCreatedEvent(this, aup));

    return aup;
  }

  @Override
  public void deleteAup() {
    IamAup aup = repo.findDefaultAup().orElseThrow(AupNotFoundError::new);
    signatureRepo.deleteByAup(aup);
    repo.delete(aup);
    eventPublisher.publishEvent(new AupDeletedEvent(this, aup));
  }

  @Override
  public IamAup updateAup(AupDTO aupDto) {

    IamAup aup = repo.findDefaultAup().orElseThrow(AupNotFoundError::new);

    aup.setDescription(aupDto.getDescription());
    aup.setUrl(aupDto.getUrl());
    aup.setSignatureValidityInDays(aupDto.getSignatureValidityInDays());
    /*
     * Due to transition from text to URL, when updating the AUP only URL is considered while text
     * is ignored and set to null
     */
    aup.setText(null);
    repo.save(aup);

    eventPublisher.publishEvent(new AupUpdatedEvent(this, aup));
    return aup;
  }

  @Override
  public IamAup touchAup() {

    long currentTimeMillis = timeProvider.currentTimeMillis();
    Date now = new Date(currentTimeMillis);

    IamAup aup = repo.findDefaultAup().orElseThrow(AupNotFoundError::new);

    aup.setLastUpdateTime(now);
    repo.save(aup);

    eventPublisher.publishEvent(new AupUpdatedEvent(this, aup));
    return aup;
  }

}
