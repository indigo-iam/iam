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

    function MyGroupsController($scope, $rootScope, $uibModal, $q, toaster, AccountGroupManagerService) {

        var self = this;

        self.$onInit = function () {
        	self.user = self.account.id;
            self.loadData();
        };

        self.loadManagedGroups = function () {
            return AccountGroupManagerService.getAccountManagedGroups(self.user).then(function (r) {
            	self.results = r.managedGroups;
            	console.debug('results', self.results);
                return r.managedGroups;
            });
        };

        self.openLoadingModal = function () {
            $rootScope.pageLoadingProgress = 0;
            self.modal = $uibModal.open({
                animation: false,
                templateUrl: '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
            });
            self.modal.result.catch(res => {
                if (res !== 'Cancel') {
                    return $q.reject(res);
                }
            });
            return self.modal.opened;
        };

        self.closeLoadingModal = function () {
        $rootScope.pageLoadingProgress = 100;
            self.modal.dismiss('Cancel');
        };

        self.handleError = function (error) {
            console.error(error);
            toaster.pop({ type: 'error', body: error });
        };

        self.loadData = function () {

            return self.openLoadingModal()
                .then(function () {
                    var promises = [];
                    promises.push(self.loadManagedGroups());
                    return $q.all(promises);
                })
                .then(function (response) {
                    self.closeLoadingModal();
                    self.loaded = true;
                })
                .catch(self.handleError);
        };
    }

    angular
        .module('dashboardApp')
        .component('myGroups', {
            templateUrl: '/resources/iam/apps/dashboard-app/components/group/managers/mygroups/mygroups.component.html',
            bindings: {
                account: '<'
            },
            controller: [
                '$scope', '$rootScope', '$uibModal', '$q', 'toaster', 'AccountGroupManagerService', MyGroupsController
            ]
        });
})();