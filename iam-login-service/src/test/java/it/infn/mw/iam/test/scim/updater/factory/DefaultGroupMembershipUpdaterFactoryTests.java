package it.infn.mw.iam.test.scim.updater.factory;

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_GROUP_MEMBERSHIP;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_GROUP_MEMBERSHIP;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.isIn;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.converter.OidcIdConverter;
import it.infn.mw.iam.api.scim.converter.SamlIdConverter;
import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.api.scim.updater.factory.DefaultGroupMembershipUpdaterFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.JacksonUtils;

@RunWith(MockitoJUnitRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DefaultGroupMembershipUpdaterFactoryTests {

  public final String GROUP_NAME = "group";
  public final IamGroup GROUP = newGroup(GROUP_NAME);

  public final String ACCOUNT_NAME1 = "member1";
  public final IamAccount ACCOUNT1 = newAccount(ACCOUNT_NAME1);
  public final ScimMemberRef ACCOUNT1_GROUP_REF =
      ScimMemberRef.builder().display(ACCOUNT1.getUsername()).value(ACCOUNT1.getUuid()).build();

  public final String ACCOUNT_NAME2 = "member2";
  public final IamAccount ACCOUNT2 = newAccount(ACCOUNT_NAME2);
  public final ScimMemberRef ACCOUNT2_GROUP_REF =
      ScimMemberRef.builder().display(ACCOUNT2.getUsername()).value(ACCOUNT2.getUuid()).build();

  ObjectMapper mapper = JacksonUtils.createJacksonObjectMapper();

  PasswordEncoder encoder = new BCryptPasswordEncoder();

  private IamAccount newAccount(String username) {
    IamAccount result = new IamAccount();
    result.setUserInfo(new IamUserInfo());

    result.setUsername(username);
    result.setUuid(UUID.randomUUID().toString());
    return result;
  }

  private IamGroup newGroup(String name) {
    IamGroup result = new IamGroup();
    result.setUuid(UUID.randomUUID().toString());
    result.setName(name);
    return result;
  }

  @Mock
  IamAccountRepository repo;

  OidcIdConverter oidcConverter = new OidcIdConverter();
  SamlIdConverter samlConverter = new SamlIdConverter();
  SshKeyConverter sshKeyConverter = new SshKeyConverter();
  X509CertificateConverter x509Converter = new X509CertificateConverter();

  DefaultGroupMembershipUpdaterFactory factory;

  private void addMember(IamAccount a, IamGroup g) {
    a.setGroups(Sets.newHashSet(g));
    g.getAccounts().add(a);
  }

  @Before
  public void init() {
    factory = new DefaultGroupMembershipUpdaterFactory(repo);
  }

  @Test
  public void testAddMembershipPatchOpParsing() {

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().add(Lists.newArrayList(ACCOUNT1_GROUP_REF)).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(1));

    assertThat(updaters.get(0).getType(), equalTo(ACCOUNT_ADD_GROUP_MEMBERSHIP));
    assertThat(updaters.get(0).update(), equalTo(true));
    assertThat(updaters.get(0).update(), equalTo(false));

  }

  @Test(expected = ScimResourceNotFoundException.class)
  public void testAddMembershipUserNotExistsPatchOpParsing() {

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().add(Lists.newArrayList(ACCOUNT1_GROUP_REF)).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.empty());

    factory.getUpdatersForPatchOperation(GROUP, op);
  }

  @Test
  public void testAddMembershipAlreadyAMemberPatchOpParsing() {

    addMember(ACCOUNT1, GROUP);

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().add(Lists.newArrayList(ACCOUNT1_GROUP_REF)).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(1));

    assertThat(updaters.get(0).getType(), equalTo(ACCOUNT_ADD_GROUP_MEMBERSHIP));
    assertThat(updaters.get(0).update(), equalTo(false));  }

  @Test
  public void testAddMultipleMembershipPatchOpParsing() {

    ScimGroupPatchRequest req = ScimGroupPatchRequest.builder()
      .add(Lists.newArrayList(ACCOUNT1_GROUP_REF, ACCOUNT2_GROUP_REF))
      .build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));
    when(repo.findByUuid(ACCOUNT2.getUuid())).thenReturn(Optional.of(ACCOUNT2));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(2));

    assertThat(updaters.get(0).getType(), equalTo(ACCOUNT_ADD_GROUP_MEMBERSHIP));
    assertThat(updaters.get(1).getType(), equalTo(ACCOUNT_ADD_GROUP_MEMBERSHIP));

    assertThat(updaters.get(0).update(), equalTo(true));
    assertThat(updaters.get(1).update(), equalTo(true));

    assertThat(updaters.get(0).update(), equalTo(false));
    assertThat(updaters.get(1).update(), equalTo(false));
  }

  @Test(expected = ScimResourceNotFoundException.class)
  public void testAddMultipleMembershipOneUserNotExistsPatchOpParsing() {

    ScimGroupPatchRequest req = ScimGroupPatchRequest.builder()
      .add(Lists.newArrayList(ACCOUNT1_GROUP_REF, ACCOUNT2_GROUP_REF))
      .build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));
    when(repo.findByUuid(ACCOUNT2.getUuid())).thenReturn(Optional.empty());

    factory.getUpdatersForPatchOperation(GROUP, op);
  }

  @Test
  public void testRemoveMembershipPatchOpParsing() {

    addMember(ACCOUNT1, GROUP);

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().remove(Lists.newArrayList(ACCOUNT1_GROUP_REF)).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(1));

    assertThat(updaters.get(0).getType(), equalTo(ACCOUNT_REMOVE_GROUP_MEMBERSHIP));
    assertThat(updaters.get(0).update(), equalTo(true));
    assertThat(updaters.get(0).update(), equalTo(false));

  }

  @Test(expected = ScimResourceNotFoundException.class)
  public void testRemoveMembershipUserNotExistsPatchOpParsing() {

    ScimGroupPatchRequest req = ScimGroupPatchRequest.builder()
      .remove(Lists.newArrayList(ACCOUNT1_GROUP_REF))
      .build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.empty());

    factory.getUpdatersForPatchOperation(GROUP, op);
  }

  @Test(expected = ScimResourceNotFoundException.class)
  public void testRemoveMultipleMembershipUserNotExistsPatchOpParsing() {

    ScimGroupPatchRequest req = ScimGroupPatchRequest.builder()
      .remove(Lists.newArrayList(ACCOUNT1_GROUP_REF, ACCOUNT2_GROUP_REF))
      .build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));
    when(repo.findByUuid(ACCOUNT2.getUuid())).thenReturn(Optional.empty());

    factory.getUpdatersForPatchOperation(GROUP, op);
  }

  @Test
  public void testRemoveMultipleMembershipPatchOpParsing() {

    addMember(ACCOUNT1, GROUP);
    addMember(ACCOUNT2, GROUP);

    ScimGroupPatchRequest req = ScimGroupPatchRequest.builder()
      .remove(Lists.newArrayList(ACCOUNT1_GROUP_REF, ACCOUNT2_GROUP_REF))
      .build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));
    when(repo.findByUuid(ACCOUNT2.getUuid())).thenReturn(Optional.of(ACCOUNT2));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(2));

    assertThat(updaters.get(0).getType(), equalTo(ACCOUNT_REMOVE_GROUP_MEMBERSHIP));
    assertThat(updaters.get(1).getType(), equalTo(ACCOUNT_REMOVE_GROUP_MEMBERSHIP));

    assertThat(updaters.get(0).update(), equalTo(true));
    assertThat(updaters.get(1).update(), equalTo(true));

    assertThat(updaters.get(0).update(), equalTo(false));
    assertThat(updaters.get(1).update(), equalTo(false));
  }

  @Test
  public void testRemoveMembershipNotAMemberPatchOpParsing() {

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().remove(Lists.newArrayList(ACCOUNT1_GROUP_REF)).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(1));

    assertThat(updaters.get(0).getType(), equalTo(ACCOUNT_REMOVE_GROUP_MEMBERSHIP));
    assertThat(updaters.get(0).update(), equalTo(false));
  }

  @Test
  public void testReplaceMembershipPatchOpParsing() {

    addMember(ACCOUNT1, GROUP);

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().replace(Lists.newArrayList(ACCOUNT2_GROUP_REF)).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));
    when(repo.findByUuid(ACCOUNT2.getUuid())).thenReturn(Optional.of(ACCOUNT2));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(2));

    List<UpdaterType> updaterTypes =
        Lists.newArrayList(ACCOUNT_REMOVE_GROUP_MEMBERSHIP, ACCOUNT_ADD_GROUP_MEMBERSHIP);

    assertThat(updaters.get(0).getType(), Matchers.isIn(updaterTypes));
    assertThat(updaters.get(1).getType(), Matchers.isIn(updaterTypes));

    updaters.forEach(u -> assertThat(u.update(), equalTo(true)));

  }

  @Test
  public void testReplaceMembershipWithEmptySetPatchOpParsing() {

    addMember(ACCOUNT1, GROUP);

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().replace(Lists.newArrayList()).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(1));

    assertThat(updaters.get(0).getType(), equalTo(ACCOUNT_REMOVE_GROUP_MEMBERSHIP));

    updaters.forEach(u -> assertThat(u.update(), equalTo(true)));

  }

  @Test
  public void testReplaceMembershipFromEmptySetPatchOpParsing() {

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().replace(Lists.newArrayList(ACCOUNT1_GROUP_REF)).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(ACCOUNT1.getUuid())).thenReturn(Optional.of(ACCOUNT1));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(GROUP, op);

    assertThat(updaters.size(), equalTo(1));

    assertThat(updaters.get(0).getType(), equalTo(ACCOUNT_ADD_GROUP_MEMBERSHIP));

    updaters.forEach(u -> assertThat(u.update(), equalTo(true)));

  }

  @Test
  public void testReplaceMembershipWithCommonMembersPatchOpParsing() {

    IamGroup group = newGroup("group");
    IamAccount member = newAccount("member");
    member.getGroups().add(group);
    IamAccount memberToRemove = newAccount("memberToRemove");
    memberToRemove.getGroups().add(group);
    group.setAccounts(Sets.newHashSet(member, memberToRemove));
    IamAccount memberToAdd = newAccount("memberToAdd");

    ScimMemberRef memberRef1 =
        ScimMemberRef.builder().display(member.getUsername()).value(member.getUuid()).build();
    ScimMemberRef memberRef2 = ScimMemberRef.builder()
      .display(memberToAdd.getUsername())
      .value(memberToAdd.getUuid())
      .build();

    ScimGroupPatchRequest req =
        ScimGroupPatchRequest.builder().replace(Lists.newArrayList(memberRef1, memberRef2)).build();

    ScimPatchOperation<List<ScimMemberRef>> op = req.getOperations().get(0);

    when(repo.findByUuid(member.getUuid())).thenReturn(Optional.of(member));
    when(repo.findByUuid(memberToRemove.getUuid())).thenReturn(Optional.of(memberToRemove));
    when(repo.findByUuid(memberToAdd.getUuid())).thenReturn(Optional.of(memberToAdd));

    List<AccountUpdater> updaters = factory.getUpdatersForPatchOperation(group, op);

    assertThat(updaters.size(), equalTo(2));

    List<UpdaterType> updaterTypes =
        Lists.newArrayList(ACCOUNT_REMOVE_GROUP_MEMBERSHIP, ACCOUNT_ADD_GROUP_MEMBERSHIP);

    assertThat(updaters.get(0).getType(), isIn(updaterTypes));
    assertThat(updaters.get(1).getType(), isIn(updaterTypes));

    updaters.forEach(u -> assertThat(u.update(), equalTo(true)));

  }
}
