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

    function GroupController($state, Utils, GroupService) {
        var self = this;

        self.loadGroup = loadGroup;
        self.id = $state.params.id;
        self.voAdmin = false;
        self.groupManager = false;

        self.$onInit = function () {
            self.groupManager = Utils.isGroupManagerForGroup(self.group.id);
            self.voAdmin = Utils.isAdmin();
        };

        function loadGroup() {
            return GroupService.getGroup(self.id).then(function (result) {
                self.group = result;
                return result;
            });
        }
    }

    angular.module('dashboardApp').component('group', {
        templateUrl: '/resources/iam/apps/dashboard-app/components/group/group.component.html',
        bindings: {
            group: '=',
            labels: '='
        },
        controller: [
            '$state', 'Utils', 'GroupService', GroupController
        ]
    });
})();