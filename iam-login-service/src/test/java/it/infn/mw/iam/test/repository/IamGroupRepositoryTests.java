package it.infn.mw.iam.test.repository;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.TransactionSystemException;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class})
public class IamGroupRepositoryTests {

  @Autowired
  private IamGroupRepository groupRepository;

  private IamGroup parent;
  private IamGroup child;


  @After
  public void tearDown() {
    if (child != null) {
      deleteGroup(child);
    }
    if (parent != null) {
      deleteGroup(parent);
    }
  }

  @Test
  public void createParentGroup() {

    parent = createGroup(null);

    IamGroup group = groupRepository.findByUuid(parent.getUuid()).get();
    Assert.assertNotNull(group);
    Assert.assertNull(group.getParentGroup());
    Assert.assertThat(group.getChildrenGroups(), Matchers.empty());
  }

  @Test
  public void createNestedGroup() {

    parent = createGroup(null);
    child = createGroup(parent);

    IamGroup group = groupRepository.findByUuid(child.getUuid()).get();
    Assert.assertNotNull(group.getParentGroup());
    Assert.assertEquals(parent.getUuid(), group.getParentGroup().getUuid());

    group = groupRepository.findByUuid(parent.getUuid()).get();
    Assert.assertThat(group.getChildrenGroups(), Matchers.not(Matchers.empty()));
    Assert.assertThat(child, Matchers.isIn(group.getChildrenGroups()));
  }

  @Test
  public void deleteNestedGroup() {

    parent = createGroup(null);
    child = createGroup(parent);

    IamGroup group = groupRepository.findByUuid(child.getUuid()).get();
    groupRepository.delete(group);
    Set<IamGroup> children = parent.getChildrenGroups();
    children.remove(child);
    parent.setChildrenGroups(children);

    groupRepository.save(parent);

    group = groupRepository.findByUuid(parent.getUuid()).get();
    Assert.assertThat(group.getChildrenGroups(), Matchers.empty());
  }

  @Test
  public void deleteNotEmptyParentGroup() {
    parent = createGroup(null);
    child = createGroup(parent);

    try {
      groupRepository.delete(parent);
    } catch (Exception e) {
      Assert.assertThat(e, Matchers.instanceOf(TransactionSystemException.class));
    }
  }

  @Test
  public void listAllRootGroups() {
    List<IamGroup> rootGroups = groupRepository.findRootGroups();
    int count = rootGroups.size();

    parent = createGroup(null);
    Assert.assertEquals(count + 1, groupRepository.findRootGroups().size());
  }

  @Test
  public void listSubgroups() {
    parent = createGroup(null);
    List<IamGroup> subgroups = groupRepository.findSubgroups(parent);
    Assert.assertThat(subgroups, Matchers.empty());

    child = createGroup(parent);
    subgroups = groupRepository.findSubgroups(parent);
    Assert.assertEquals(1, subgroups.size());
  }


  private IamGroup createGroup(IamGroup parentGroup) {
    String uuid = UUID.randomUUID().toString();
    IamGroup group = new IamGroup();
    group.setName(uuid);
    group.setUuid(uuid);
    group.setCreationTime(new Date());
    group.setLastUpdateTime(new Date());
    group.setParentGroup(parentGroup);
    groupRepository.save(group);

    if (parentGroup != null) {
      Set<IamGroup> children = parentGroup.getChildrenGroups();
      children.add(group);
      parentGroup.setChildrenGroups(children);
      groupRepository.save(parentGroup);
    }

    return group;
  }

  private void deleteGroup(IamGroup group) {
    IamGroup parent = group.getParentGroup();
    if (parent != null) {
      Set<IamGroup> children = parent.getChildrenGroups();
      children.remove(group);
      parent.setChildrenGroups(children);
      groupRepository.save(parent);
    }
    groupRepository.delete(group);
  }

}
