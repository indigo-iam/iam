package it.infn.mw.iam.persistence.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.IamGroup;

public interface IamGroupRepository extends PagingAndSortingRepository<IamGroup, Long> {

  @Query("select count(g) from IamGroup g")
  int countAllGroups();

  Optional<IamGroup> findByUuid(@Param("uuid") String uuid);

  Optional<IamGroup> findByName(@Param("name") String name);

  @Query("select g from IamGroup g where g.name = :name and g.uuid != :uuid")
  Optional<IamGroup> findByNameWithDifferentId(@Param("name") String name,
      @Param("uuid") String uuid);

  @Query("select g from IamGroup g where g.parentGroup is null")
  List<IamGroup> findRootGroups();

  @Query("select g from IamGroup g where g.parentGroup = :parentGroup")
  List<IamGroup> findSubgroups(@Param("parentGroup") IamGroup parentGroup);

}
