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

    function ClientOwnersController(ClientsService, $uibModal, toaster, Utils, $location) {
        var self = this;

        self.assignOwner = assignOwner;
        self.addOwnerByUsername = addOwnerByUsername;
        self.removeOwner = removeOwner;
        self.canRemove = canRemove;
        self.onChangePage = onChangePage;

        self.$onInit = function () {
            console.debug('ClientOwnersController.self', self);
            self.currentPage = 1;
            self.itemsPerPage = 10;
        };

        function onChangePage() {
            loadClientOwners();
        }

        function loadClientOwners() {
            var startIndex = (self.currentPage - 1) * self.itemsPerPage + 1;

            return ClientsService.retrieveClientOwners(self.client.client_id, startIndex, self.itemsPerPage).then(res => {
                if (self.currentPage > 1 && (!res.Resources || res.Resources.length === 0)) {
                    self.currentPage--;
                    return loadClientOwners();
                }
                self.clientOwners = res;
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: "Error fetching client owners"
                });
            });
        }

        function canRemove(user, index) {
            if (Utils.isAdmin()) {
                return true;
            }
            if (Utils.isMe(user.id)) {
                return self.clientOwners.totalResults > 1;
            }
            return index > self.clientOwners.Resources.findIndex(o => Utils.isMe(o.id));
        }

        function removeOwner(user) {
            ClientsService.removeClientOwner(self.client.client_id, user.id).then(res => {
                if (Utils.isMe(user.id) && !Utils.isAdmin()) {
                    toaster.pop({
                        type: 'success',
                        body: 'You are no longer an owner of this client'
                    });
                    $location.path('/home/clients');
                    return;
                }
                loadClientOwners();
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: (err.data && err.data.error) || "Error removing client owner"
                });
            });
        }

        function addOwnerByUsername() {
            ClientsService.assignClientOwnerByUsername(self.client.client_id, self.newOwnerUsername).then(res => {
                self.newOwnerUsername = '';
                loadClientOwners();
                toaster.pop({
                    type: 'success',
                    body: 'Owner added'
                });
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: (err.data && err.data.error) || "Error assigning client owner"
                });
            });
        }

        function assignOwner() {
            var modalInstance = $uibModal.open({
                component: 'findUserDialog',
                resolve: {
                    title: function () {
                        return 'Assign client owner';
                    },
                    action: function () {
                        return 'Assign owner';
                    }
                }
            });

            modalInstance.result.then(user => {
                console.log("Selected user: ", user);
                ClientsService.assignClientOwner(self.client.client_id, user.id).then(res => {
                    loadClientOwners();
                }).catch(err => {
                    toaster.pop({
                        type: 'error',
                        body: "Error assigning client owner"
                    });
                });
            });
        }
    }

    angular
        .module('dashboardApp')
        .component('clientOwners', component());


    function component() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/clientowners/clientowners.component.html",
            bindings: {
                client: '=',
                clientOwners: '='
            },
            controller: ['ClientsService', '$uibModal', 'toaster', 'Utils', '$location', ClientOwnersController],
            controllerAs: '$ctrl'
        };
    }

}());