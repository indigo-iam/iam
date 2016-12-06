package it.infn.mw.iam.authn;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.authn.error.AccountAlreadyLinkedError;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class DefaultExternalAccountLinker implements ExternalAccountLinker {

  final IamAccountRepository repo;
  final SamlUserIdentifierResolver samlUserIdResolver;

  @Autowired
  public DefaultExternalAccountLinker(IamAccountRepository repo,
      SamlUserIdentifierResolver resolver) {
    this.repo = repo;
    this.samlUserIdResolver = resolver;
  }

  @Override
  public void linkToIamAccount(IamAccount targetAccount, OidcExternalAuthenticationToken token) {

    final String oidcSubject = token.getExternalAuthentication().getSub();
    final String oidcIssuer = token.getExternalAuthentication().getIssuer();

    repo.findByOidcId(oidcIssuer, oidcSubject).ifPresent(found -> {

      if (found.equals(targetAccount)) {

	String errorMsg =
	    String.format("OpenID connect account '[%s] %s' is already linked to user '%s'",
		oidcIssuer, oidcSubject, found.getUsername());

	throw new AccountAlreadyLinkedError(errorMsg);

      } else {

	String errorMsg =
	    String.format("OpenID connect account '[%s] %s' is already linked to another user",
		oidcIssuer, oidcSubject);

	throw new AccountAlreadyLinkedError(errorMsg);
      }
    });

    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(oidcIssuer);
    oidcId.setSubject(oidcSubject);
    oidcId.setAccount(targetAccount);
    targetAccount.getOidcIds().add(oidcId);
    repo.save(targetAccount);
  }

  @Override
  public void linkToIamAccount(IamAccount targetAccount, SamlExternalAuthenticationToken token) {

    final SAMLCredential credential =
	(SAMLCredential) token.getExternalAuthentication().getCredentials();

    final String samlSubject = samlUserIdResolver.getUserIdentifier(credential)
      .orElseThrow(() -> new UsernameNotFoundException(
	  "Could not extract a user identifier from the SAML assertion"));

    final String samlIssuer = credential.getRemoteEntityID();

    repo.findBySamlId(samlIssuer, samlSubject).ifPresent(found -> {

      if (found.equals(targetAccount)) {

	String errorMsg = String.format("SAML account '[%s] %s' is already linked to user '%s'",
	    samlIssuer, samlSubject, found.getUsername());

	throw new AccountAlreadyLinkedError(errorMsg);
      } else {

	String errorMsg = String.format("SAML account '[%s] %s' is already linked to another user",
	    samlIssuer, samlSubject);

	throw new AccountAlreadyLinkedError(errorMsg);
      }

    });

    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(samlIssuer);
    samlId.setUserId(samlSubject);
    samlId.setAccount(targetAccount);
    targetAccount.getSamlIds().add(samlId);
    repo.save(targetAccount);

  }

}
