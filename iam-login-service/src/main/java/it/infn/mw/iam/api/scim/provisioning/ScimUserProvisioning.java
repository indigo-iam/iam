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
package it.infn.mw.iam.api.scim.provisioning;

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_X509_CERTIFICATE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_X509_CERTIFICATE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_ACTIVE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_EMAIL;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_FAMILY_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_GIVEN_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PASSWORD;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_SERVICE_ACCOUNT;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_USERNAME;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.domain.Page;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.OidcIdConverter;
import it.infn.mw.iam.api.scim.converter.SamlIdConverter;
import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimFilterUnsupportedException;
import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimFilter;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimListResponse.ScimListResponseBuilder;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.paging.ScimPageRequest;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.api.scim.updater.factory.DefaultAccountUpdaterFactory;
import it.infn.mw.iam.audit.events.account.AccountReplacedEvent;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.CredentialAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.UserAlreadyExistsException;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;

@Service
public class ScimUserProvisioning
    implements ScimProvisioning<ScimUser, ScimUser>, ApplicationEventPublisherAware {

  protected static final EnumSet<UpdaterType> SUPPORTED_UPDATER_TYPES =
      EnumSet.of(ACCOUNT_ADD_OIDC_ID, ACCOUNT_REMOVE_OIDC_ID, ACCOUNT_ADD_SAML_ID,
          ACCOUNT_REMOVE_SAML_ID, ACCOUNT_ADD_SSH_KEY, ACCOUNT_REMOVE_SSH_KEY,
          ACCOUNT_ADD_X509_CERTIFICATE, ACCOUNT_REMOVE_X509_CERTIFICATE, ACCOUNT_REPLACE_ACTIVE,
          ACCOUNT_REPLACE_EMAIL, ACCOUNT_REPLACE_FAMILY_NAME, ACCOUNT_REPLACE_GIVEN_NAME,
          ACCOUNT_REPLACE_PASSWORD, ACCOUNT_REPLACE_PICTURE, ACCOUNT_REPLACE_USERNAME,
          ACCOUNT_REMOVE_PICTURE, ACCOUNT_REPLACE_SERVICE_ACCOUNT);

  private final IamAccountService accountService;
  private final IamAccountRepository accountRepository;
  private final UserConverter userConverter;
  private final DefaultAccountUpdaterFactory updatersFactory;
  private final NotificationFactory notificationFactory;

  private ApplicationEventPublisher eventPublisher;

  public ScimUserProvisioning(IamAccountService accountService,
      OAuth2TokenEntityService tokenService, IamAccountRepository accountRepository,
      PasswordEncoder passwordEncoder, UserConverter userConverter, OidcIdConverter oidcIdConverter,
      SamlIdConverter samlIdConverter, SshKeyConverter sshKeyConverter,
      X509CertificateConverter x509CertificateConverter, UsernameValidator usernameValidator,
      NotificationFactory notificationFactory) {

    this.accountService = accountService;
    this.accountRepository = accountRepository;
    this.userConverter = userConverter;
    this.notificationFactory = notificationFactory;
    this.updatersFactory = new DefaultAccountUpdaterFactory(passwordEncoder, accountRepository,
        accountService, tokenService, oidcIdConverter, samlIdConverter, sshKeyConverter,
        x509CertificateConverter, usernameValidator);
  }


  // All the supported attribute Operators
  private enum AttributeOperators {
    eq, co
  }

  // All the supported filter attributes
  private enum Attributes {
    // All related to the name of the user
    familyName, givenName, username,

    // Other info
    active, emails
  }



  private ScimFilter parseFilters(final String filtersParameter) {

    if (!Strings.isNullOrEmpty(filtersParameter)) {
      // Iterating over all defined enums
      for (AttributeOperators operator : AttributeOperators.values()) {

        int from = 0;

        // Need to look at all instances that corresponds to the operator
        while (-1 != filtersParameter.indexOf(operator.toString(), from)) {

          // Looking for the first instance of the given operator in the request
          int index = filtersParameter.indexOf(operator.toString(), from);

          if (index == 0) {
            index = 1;
          } ;

          // If there is an occurence and it's surrounded by spaces
          if (filtersParameter.charAt(index - 1) == ' '
              && filtersParameter.charAt(index + operator.name().length()) == ' ') {

            // The parameter before the index is then from the start until the first space
            String parameter = filtersParameter.substring(0, index - 1);

            // The value is from the operator until the end
            String value = filtersParameter.substring(index + operator.name().length() + 1,
                filtersParameter.length());

            return new ScimFilter(parameter, operator.name(), value);

          } else {
            from = index + 1;
          }
        }
      }
    }
    throw invalidFilter(filtersParameter);
  }


  private boolean filterEvaluation(ScimFilter parsedFilters) {

    for (Attributes attribute : Attributes.values()) {
      if (attribute.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {
        for (AttributeOperators operator : AttributeOperators.values()) {
          if (operator.toString().equalsIgnoreCase(parsedFilters.getOperator())) {
            return true;
          }
        }
        return false;
      }
    }
    return false;
  }



  private Page<IamAccount> filterSearch(OffsetPageable op, ScimFilter parsedFilters) {

    Page<IamAccount> result = null;

    // Figuring out the operator
    if (AttributeOperators.eq.toString().equalsIgnoreCase(parsedFilters.getOperator())) {

      // Figuring out the attribute
      if (Attributes.givenName.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        // retrieving the results
        result = accountRepository.findByGivenName(parsedFilters.getValue(), op)
          .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.active.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        if ((parsedFilters.getValue().equalsIgnoreCase("false")
            || parsedFilters.getValue().equalsIgnoreCase("true"))) {
          result = accountRepository.findByActive(Boolean.valueOf(parsedFilters.getValue()), op)
            .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));
        } else {
          throw invalidValue(parsedFilters.getValue());
        }

      } else if (Attributes.emails.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.findByEmail(parsedFilters.getValue(), op)
          .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.username.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.findByUsername(parsedFilters.getValue(), op)
          .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.familyName.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.findByFamilyName(parsedFilters.getValue(), op)
          .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));
      }

    } else if (AttributeOperators.co.toString().equalsIgnoreCase(parsedFilters.getOperator())) {

      // Figuring out the attribute
      if (Attributes.givenName.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        // retrieving the results
        result = accountRepository.containsGivenName(parsedFilters.getValue(), op)
          .orElseThrow(() -> noUsersMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.active.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        // Contains on a boolean value makes no sense, gonna throw an error
        throw invalidOperator(parsedFilters.getOperator());


      } else if (Attributes.emails.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.containsEmail(parsedFilters.getValue(), op)
          .orElseThrow(() -> noUsersMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.username.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.containsUsername(parsedFilters.getValue(), op)
          .orElseThrow(() -> noUsersMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.familyName.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.containsFamilyName(parsedFilters.getValue(), op)
          .orElseThrow(() -> noUsersMappedToGivenName(parsedFilters.getValue()));

      }
    }

    if (result != null && result.getContent().isEmpty()) {
      throw noUsersMappedToValue(parsedFilters);
    } else if (result == null) {
      throw missingSupport(parsedFilters);
    }
    return result;
  }

  private Long filterSearch(ScimFilter parsedFilters) {

    List<IamAccount> result = null;

    // Figuring out the operator
    if (AttributeOperators.eq.toString().equalsIgnoreCase(parsedFilters.getOperator())) {

      // Figuring out the attribute
      if (Attributes.givenName.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        // retrieving the results
        result = accountRepository.findByGivenName(parsedFilters.getValue())
          .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.active.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        if ((parsedFilters.getValue().equalsIgnoreCase("false")
            || parsedFilters.getValue().equalsIgnoreCase("true"))) {
          result = accountRepository.findByActive(Boolean.valueOf(parsedFilters.getValue()))
            .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));
        } else {
          throw invalidValue(parsedFilters.getValue());
        }

      } else if (Attributes.emails.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.findMultipleByEmail(parsedFilters.getValue())
          .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.username.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = new ArrayList<>();

        result.add(accountRepository.findByUsername(parsedFilters.getValue())
          .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue())));

      } else if (Attributes.familyName.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.findByFamilyName(parsedFilters.getValue())
          .orElseThrow(() -> noUserMappedToGivenName(parsedFilters.getValue()));
      }

    } else if (AttributeOperators.co.toString().equalsIgnoreCase(parsedFilters.getOperator())) {

      // Figuring out the attribute
      if (Attributes.givenName.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        // retrieving the results
        result = accountRepository.containsGivenName(parsedFilters.getValue())
          .orElseThrow(() -> noUsersMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.active.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        // Contains on a boolean value makes no sense, gonna throw an error
        throw invalidOperator(parsedFilters.getOperator());


      } else if (Attributes.emails.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.containsEmail(parsedFilters.getValue())
          .orElseThrow(() -> noUsersMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.username.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.containsUsername(parsedFilters.getValue())
          .orElseThrow(() -> noUsersMappedToGivenName(parsedFilters.getValue()));

      } else if (Attributes.familyName.toString().equalsIgnoreCase(parsedFilters.getAttribute())) {

        result = accountRepository.containsFamilyName(parsedFilters.getValue())
          .orElseThrow(() -> noUsersMappedToGivenName(parsedFilters.getValue()));

      }
    }

    if (result != null && result.size() <= 0) {
      throw noUsersMappedToValue(parsedFilters);
    } else if (result == null) {
      throw missingSupport(parsedFilters);
    }
    return (long) result.size();
  }


  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
  }

  private void idSanityChecks(final String id) {

    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }

    if (id.trim().isEmpty()) {
      throw new IllegalArgumentException("id cannot be the empty string");
    }
  }

  private ScimResourceNotFoundException noUserMappedToId(String id) {
    return new ScimResourceNotFoundException(String.format("No user mapped to id '%s'", id));
  }

  private ScimResourceNotFoundException noUserMappedToGivenName(String name) {
    return new ScimResourceNotFoundException(
        String.format("No user mapped to givenName \"%s\"", name));
  }

  private ScimResourceNotFoundException noUsersMappedToGivenName(String name) {
    return new ScimResourceNotFoundException(
        String.format("There are no users mapped to the givenName \"%s\"", name));
  }

  private ScimResourceNotFoundException noUsersMappedToValue(ScimFilter filter) {
    return new ScimResourceNotFoundException(String.format(
        "the filter \"%s,%s,%s\" produced no results as no data fulfilled the criteria.",
        filter.getAttribute(), filter.getOperator(), filter.getValue()));
  }

  private IllegalArgumentException invalidValue(String value) {
    return new IllegalArgumentException(
        String.format("the value \"%s\" does not fulfill the filtering convention", value));
  }


  private IllegalArgumentException invalidFilter(String filter) {
    return new IllegalArgumentException(
        String.format("the filter \"%s\" does not fulfill the filtering convention", filter));
  }

  private IllegalArgumentException invalidOperator(String operator) {
    return new IllegalArgumentException(String
      .format("the operator \"%s\" can not be used with the given filtering attribute", operator));
  }

  private ScimFilterUnsupportedException missingSupport(ScimFilter filter) {
    return new ScimFilterUnsupportedException(String.format(
        "the filter \"%s,%s,%s\" is within the documentation, but is missing current support.",
        filter.getAttribute(), filter.getOperator(), filter.getValue()));
  }

  private ScimResourceExistsException usernameAlreadyAssigned(String username) {
    return new ScimResourceExistsException(
        String.format("username %s already assigned to another user", username));
  }

  private ScimResourceExistsException emailAlreadyAssigned(String email) {
    return new ScimResourceExistsException(
        String.format("email %s already assigned to another user", email));
  }

  private ScimPatchOperationNotSupported notSupportedPatchOp(String op) {
    return new ScimPatchOperationNotSupported(String.format("%s not supported", op));
  }

  @Override
  public ScimUser getById(final String id) {

    idSanityChecks(id);

    IamAccount account = accountRepository.findByUuid(id).orElseThrow(() -> noUserMappedToId(id));

    return userConverter.dtoFromEntity(account);

  }

  @Override
  public void delete(final String id) {

    idSanityChecks(id);

    IamAccount account = accountRepository.findByUuid(id).orElseThrow(() -> noUserMappedToId(id));

    accountService.deleteAccount(account);

  }

  @Override
  public ScimUser create(final ScimUser user) {

    IamAccount newAccount = userConverter.entityFromDto(user);

    try {
      IamAccount account = accountService.createAccount(newAccount);
      return userConverter.dtoFromEntity(account);
    } catch (CredentialAlreadyBoundException | UserAlreadyExistsException e) {
      throw new ScimResourceExistsException(e.getMessage(), e);
    }
  }

  @Override
  public ScimListResponse<ScimUser> list(final ScimPageRequest params) {

    ScimListResponseBuilder<ScimUser> builder = ScimListResponse.builder();

    if (params.getCount() == 0) {

      long totalResults = accountRepository.count();
      builder.totalResults(totalResults);

    } else {

      OffsetPageable op = new OffsetPageable(params.getStartIndex(), params.getCount());

      Page<IamAccount> results = accountRepository.findAll(op);

      List<ScimUser> resources = new ArrayList<>();

      results.getContent().forEach(a -> resources.add(userConverter.dtoFromEntity(a)));

      builder.resources(resources);
      builder.fromPage(results, op);
    }

    return builder.build();
  }



  // Method to fetch users according to a filter
  @Override
  public ScimListResponse<ScimUser> list(final ScimPageRequest params, String filter) {

    ScimListResponseBuilder<ScimUser> builder = ScimListResponse.builder();

    OffsetPageable op;
    Page<IamAccount> results;

    // Do the filtersearch
    if (filter != null) {
      ScimFilter parsedFilters = parseFilters(filter);

      if (!filterEvaluation(parsedFilters)) {
        throw invalidFilter(filter);
      }

      if (params.getCount() == 0) {
        long totalResults = filterSearch(parsedFilters);
        builder.totalResults(totalResults);
        return builder.build();

      } else {
        op = new OffsetPageable(params.getStartIndex(), params.getCount());

        results = filterSearch(op, parsedFilters);
      }


    } else {
      // Don't do a filtersearch

      if (params.getCount() == 0) {

        long totalResults = accountRepository.count();
        builder.totalResults(totalResults);
        return builder.build();

      } else {
        op = new OffsetPageable(params.getStartIndex(), params.getCount());
        results = accountRepository.findAll(op);
      }


    }

    List<ScimUser> resources = new ArrayList<>();

    results.getContent().forEach(a -> resources.add(userConverter.dtoFromEntity(a)));

    builder.resources(resources);
    builder.fromPage(results, op);

    return builder.build();
  }

  @Override
  public ScimUser replace(final String uuid, final ScimUser scimItemToBeUpdated) {

    // user must exist
    IamAccount existingAccount =
        accountRepository.findByUuid(uuid).orElseThrow(() -> noUserMappedToId(uuid));

    // username must be available
    final String username = scimItemToBeUpdated.getUserName();
    if (accountRepository.findByUsernameWithDifferentUUID(username, uuid).isPresent()) {
      throw usernameAlreadyAssigned(username);
    }

    // email must be unique
    final String updatedEmail = scimItemToBeUpdated.getEmails().get(0).getValue();
    if (accountRepository.findByEmailWithDifferentUUID(updatedEmail, uuid).isPresent()) {
      throw emailAlreadyAssigned(updatedEmail);
    }

    IamAccount updatedAccount = userConverter.entityFromDto(scimItemToBeUpdated);

    updatedAccount.setId(existingAccount.getId());
    updatedAccount.setUuid(existingAccount.getUuid());
    updatedAccount.setCreationTime(existingAccount.getCreationTime());

    // If the active field was not provided in the input scim user,
    // use the value that was formerly set in the database
    if (scimItemToBeUpdated.getActive() == null) {
      updatedAccount.setActive(existingAccount.isActive());
    }

    updatedAccount.touch();

    accountRepository.save(updatedAccount);

    eventPublisher.publishEvent(new AccountReplacedEvent(this, updatedAccount, existingAccount,
        String.format("Replaced user %s with new user %s", updatedAccount.getUsername(),
            existingAccount.getUsername())));

    return userConverter.dtoFromEntity(updatedAccount);
  }

  private void executePatchOperation(IamAccount account, ScimPatchOperation<ScimUser> op) {

    List<AccountUpdater> updaters = updatersFactory.getUpdatersForPatchOperation(account, op);
    List<AccountUpdater> updatesToPublish = new ArrayList<>();

    boolean oneUpdaterChangedAccount = false;

    for (AccountUpdater u : updaters) {
      if (!SUPPORTED_UPDATER_TYPES.contains(u.getType())) {
        throw notSupportedPatchOp(u.getType().getDescription());
      }

      boolean lastUpdaterChangedAccount = u.update();

      oneUpdaterChangedAccount |= lastUpdaterChangedAccount;

      if (lastUpdaterChangedAccount) {
        updatesToPublish.add(u);
      }
    }

    if (oneUpdaterChangedAccount) {

      account.touch();
      accountRepository.save(account);
      for (AccountUpdater u : updatesToPublish) {
        u.publishUpdateEvent(this, eventPublisher);
        handleSpecificUpdateType(account, u);
      }

    }
  }

  private void handleSpecificUpdateType(IamAccount account, AccountUpdater u) {
    if (ACCOUNT_REPLACE_ACTIVE.equals(u.getType())) {
      if (account.isActive()) {
        notificationFactory.createAccountRestoredMessage(account);
      } else {
        notificationFactory.createAccountSuspendedMessage(account);
      }
    }
    if (ACCOUNT_REPLACE_SERVICE_ACCOUNT.equals(u.getType())) {
      if (account.isServiceAccount()) {
        notificationFactory.createSetAsServiceAccountMessage(account);
      } else {
        notificationFactory.createRevokeServiceAccountMessage(account);
      }
    }
  }

  @Override
  public void update(final String id, final List<ScimPatchOperation<ScimUser>> operations) {

    IamAccount account = accountRepository.findByUuid(id).orElseThrow(() -> noUserMappedToId(id));

    operations.forEach(op -> executePatchOperation(account, op));
  }

}
