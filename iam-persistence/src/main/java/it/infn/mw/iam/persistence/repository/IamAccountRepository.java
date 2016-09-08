package it.infn.mw.iam.persistence.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.IamAccount;

public interface IamAccountRepository extends PagingAndSortingRepository<IamAccount, Long> {

  @Query("select count(a) from IamAccount a")
  int countAllUsers();

  Optional<IamAccount> findByUuid(@Param("uuid") String uuid);

  Optional<IamAccount> findByUsername(@Param("username") String username);

  @Query("select a from IamAccount a join a.samlIds si where si.idpId = :idpId and si.userId = :subject")
  Optional<IamAccount> findBySamlId(@Param("idpId") String idpId, @Param("subject") String subject);

  @Query("select a from IamAccount a join a.oidcIds oi where oi.issuer = :issuer and oi.subject = :subject")
  Optional<IamAccount> findByOidcId(@Param("issuer") String issuer,
      @Param("subject") String subject);

  @Query("select a from IamAccount a join a.sshKeys sk where sk.fingerprint = :fingerprint")
  Optional<IamAccount> findBySshKeyFingerprint(@Param("fingerprint") String fingerprint);

  @Query("select a from IamAccount a join a.sshKeys sk where sk.label = :label")
  Optional<IamAccount> findBySshKeyLabel(@Param("label") String label);

  @Query("select a from IamAccount a join a.sshKeys sk where sk.value = :value")
  Optional<IamAccount> findBySshKeyValue(@Param("value") String value);

  @Query("select a from IamAccount a join a.userInfo ui where ui.email = :emailAddress")
  Optional<IamAccount> findByEmail(@Param("emailAddress") String emailAddress);

  @Query("select a from IamAccount a where a.username = :username and a.uuid != :uuid")
  Optional<IamAccount> findByUsernameWithDifferentId(@Param("username") String username,
      @Param("uuid") String uuid);

  @Query("select a from IamAccount a join a.x509Certificates c where c.certificateSubject = :subject")
  Optional<IamAccount> findByCertificateSubject(@Param("subject") String subject);

  @Query("select a from IamAccount a join a.groups ag where ag.id = :groupId")
  List<IamAccount> findByGroupId(@Param("groupId") Long groupId);

  Optional<IamAccount> findByConfirmationKey(@Param("confirmationKey") String confirmationKey);

  Optional<IamAccount> findByResetKey(@Param("resetKey") String resetKey);
}
