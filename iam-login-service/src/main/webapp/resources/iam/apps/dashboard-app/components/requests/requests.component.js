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
(function() {
    'use strict';

    function RequestsController(Utils, toaster) {
        var self = this;

        self.$onInit = function() {
            self.voAdmin = Utils.isAdmin();
            self.groupManager = Utils.isGroupManager();
            self.privileged = self.voAdmin || self.groupManager;

            if (self.voAdmin) {
                self.activeTab = 1;
            } else if (self.groupManager) {
                self.activeTab = 2;
            }
        };
    }

    angular
        .module('dashboardApp')
        .component('requests', component());

    function component() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/requests/requests.component.html",
            controller: ['Utils', 'toaster', RequestsController],
            controllerAs: '$ctrl'
        };
    }
}());