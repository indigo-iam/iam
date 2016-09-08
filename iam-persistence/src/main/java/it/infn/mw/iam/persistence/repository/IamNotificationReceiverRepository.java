package it.infn.mw.iam.persistence.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import it.infn.mw.iam.persistence.model.IamNotificationReceiver;

public interface IamNotificationReceiverRepository
    extends PagingAndSortingRepository<IamNotificationReceiver, Long> {

}
