/*
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
(function () {
    'use strict';

    function GroupInfoController(GroupsService, LabelsService, $q, $scope, toaster) {
        var self = this;

        self.makeOptional = makeOptional;

        self.isOptionalGroup = false;

        const VOMS_ROLE_LABEL = { "name": "voms.role" };
        const OPTIONAL_GROUP_LABEL = { "name": "wlcg.optional-group" };

        const labels = [VOMS_ROLE_LABEL, OPTIONAL_GROUP_LABEL];

        self.$onInit = function () {
            console.debug('GroupInfoController.self', self);
            $scope.$watch(self.labels, function (newVal, oldVal) {
                updateIsOptionalGroup();
            }, true);
            updateIsOptionalGroup();
        };

        function hasLabel(label) {
            var found = false;
            self.labels.forEach(l => {
                if (l.name === label.name && l.prefix === label.prefix) {
                    found = true;
                }
            });

            return found;
        }
        function updateIsOptionalGroup() {
            var hasVoms = hasLabel(VOMS_ROLE_LABEL);
            var hasOpt = hasLabel(OPTIONAL_GROUP_LABEL);
            self.isOptionalGroup = hasVoms && hasOpt;
        }

        function makeOptional() {
            var promises = [];

            promises.push(LabelsService.setGroupLabel(self.group.id, VOMS_ROLE_LABEL));
            promises.push(LabelsService.setGroupLabel(self.group.id, OPTIONAL_GROUP_LABEL));

            $q.all(promises).then(res => {
                LabelsService.getGroupLabels(self.group.id).then(labels => {
                    self.labels = labels;
                    self.parent.loadGroup();
                    updateIsOptionalGroup();
                    toaster.pop({ "type": 'success', "body": "Group " + self.group.displayName + " is now an optional group" });
                });

            }).catch(res => {
                toaster.pop({ "type": 'error', "body": "Error marking group as optional group" });
            });
        }
    }

    angular
        .module('dashboardApp')
        .component('groupInfo', groupinfo());

    function groupinfo() {

        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/group/groupinfo/groupinfo.component.html",
            require: {
                parent: '^group'
            },
            bindings: {
                group: '=',
                labels: '='
            },
            controller: ['GroupsService', 'LabelsService', '$q', '$scope', 'toaster', GroupInfoController],
            controllerAs: '$ctrl'
        };
    }

}());