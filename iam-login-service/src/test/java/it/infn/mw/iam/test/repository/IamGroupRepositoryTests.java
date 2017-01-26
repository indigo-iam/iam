package it.infn.mw.iam.test.repository;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.isIn;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.junit.After;
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
    assertNotNull(group);
    assertNull(group.getParentGroup());
    assertThat(group.getChildrenGroups(), empty());
  }

  @Test
  public void createNestedGroup() {

    parent = createGroup(null);
    child = createGroup(parent);

    IamGroup group = groupRepository.findByUuid(child.getUuid()).get();
    assertNotNull(group.getParentGroup());
    assertEquals(parent.getUuid(), group.getParentGroup().getUuid());

    group = groupRepository.findByUuid(parent.getUuid()).get();
    assertThat(group.getChildrenGroups(), not(empty()));
    assertThat(child, isIn(group.getChildrenGroups()));
  }

  @Test
  public void deleteNestedGroup() {

    parent = createGroup(null);
    child = createGroup(parent);

    IamGroup group = groupRepository.findByUuid(child.getUuid()).get();
    groupRepository.delete(group);
    parent.getChildrenGroups().remove(child);

    groupRepository.save(parent);

    group = groupRepository.findByUuid(parent.getUuid()).get();
    assertThat(group.getChildrenGroups(), empty());
  }

  @Test
  public void deleteNotEmptyParentGroup() {
    parent = createGroup(null);
    child = createGroup(parent);

    try {
      groupRepository.delete(parent);
    } catch (Exception e) {
      assertThat(e, instanceOf(TransactionSystemException.class));
    }
  }

  @Test
  public void listAllRootGroups() {
    List<IamGroup> rootGroups = groupRepository.findRootGroups();
    int count = rootGroups.size();

    parent = createGroup(null);
    assertEquals(count + 1, groupRepository.findRootGroups().size());
  }

  @Test
  public void listSubgroups() {
    parent = createGroup(null);
    List<IamGroup> subgroups = groupRepository.findSubgroups(parent);
    assertThat(subgroups, empty());

    child = createGroup(parent);
    subgroups = groupRepository.findSubgroups(parent);
    assertEquals(1, subgroups.size());
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
      parentGroup.getChildrenGroups().add(group);
      groupRepository.save(parentGroup);
    }

    return group;
  }

  private void deleteGroup(IamGroup group) {
    IamGroup parent = group.getParentGroup();
    if (parent != null) {
      parent.getChildrenGroups().remove(group);
      groupRepository.save(parent);
    }
    groupRepository.delete(group);
  }

}
