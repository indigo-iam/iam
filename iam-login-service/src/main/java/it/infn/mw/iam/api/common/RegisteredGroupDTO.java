package it.infn.mw.iam.api.common;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;

public class RegisteredGroupDTO implements Serializable {
    private Long id;
    private String uuid;
    private String name;
    private String description;
    private RegisteredGroupDTO parentGroup;
    private Set<RegisteredGroupDTO> childrenGroups = new HashSet<>();
    private Set<IamLabel> labels = new HashSet<>();

    private RegisteredGroupDTO(Builder builder) {
        this.id = builder.id;
        this.uuid = builder.uuid;
        this.name = builder.name;
        this.description = builder.description;
        this.parentGroup = builder.parentGroup;
        this.childrenGroups = builder.childrenGroups != null ? builder.childrenGroups : new HashSet<>();
        this.labels = builder.labels != null ? builder.labels : new HashSet<>();
    }

    public static class Builder {
        private Long id;
        private String uuid;
        private String name;
        private String description;
        private RegisteredGroupDTO parentGroup;
        private Set<RegisteredGroupDTO> childrenGroups;
        private Set<IamLabel> labels;

        public Builder id(Long id) {
            this.id = id;
            return this;
        }

        public Builder uuid(String uuid) {
            this.uuid = uuid;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder parentGroup(IamGroup parentGroup) {
            if (parentGroup != null) {
                this.parentGroup = new RegisteredGroupDTO.Builder()
                        .id(parentGroup.getId())
                        .uuid(parentGroup.getUuid())
                        .name(parentGroup.getName())
                        .description(parentGroup.getDescription())
                        .parentGroup(parentGroup.getParentGroup())
                        // .childrenGroups(parentGroup.getChildrenGroups())
                        .labels(parentGroup.getLabels())
                        .build();
            }
            return this;
        }

        public Builder childrenGroups(Set<IamGroup> childrenGroups) {
            this.childrenGroups = childrenGroups.stream()
                    .map(gr -> new RegisteredGroupDTO.Builder()
                            .id(gr.getId())
                            .uuid(gr.getUuid())
                            .name(gr.getName())
                            .description(gr.getDescription())
                            //.parentGroup(gr.getParentGroup())
                            .childrenGroups(gr.getChildrenGroups())
                            .labels(gr.getLabels())
                            .build())
                    .collect(Collectors.toSet());
            return this;
        }

        public Builder labels(Set<IamLabel> labels) {
            this.labels = labels;
            return this;
        }

        public RegisteredGroupDTO build() {
            return new RegisteredGroupDTO(this);
        }
    }

    public Long getId() {
        return id;
    }

    public String getUuid() {
        return uuid;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public RegisteredGroupDTO getParentGroup() {
        return parentGroup;
    }

    public Set<RegisteredGroupDTO> getChildrenGroups() {
        return childrenGroups;
    }

    public Set<IamLabel> getLabels() {
        return labels;
    }

}
