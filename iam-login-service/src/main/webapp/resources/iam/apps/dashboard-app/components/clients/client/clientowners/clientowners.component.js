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

    function ClientOwnersController(ClientsService, $uibModal, toaster) {
        var self = this;

        self.assignOwner = assignOwner;
        self.removeOwner = removeOwner;
        self.onChangePage = onChangePage;

        self.$onInit = function () {
            console.debug('ClientOwnersController.self', self);
            self.currentPage = 1;
            self.itemsPerPage = 10;
        };

        function onChangePage() {
            var currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;

            if (currentOffset > self.totalResults && self.currentPage > 1) {
                self.currentPage--;
                currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;
            }

            self.updateClientOwners(currentOffset, self.itemsPerPage).then(res => {
                self.totalResults = res.totalResults;
            });
        }

        function updateClientOwners(startIndex, itemsPerPage) {
            ClientsService.retrieveClientOwners(self.client.client_id, startIndex, itemsPerPage).then(res => {
                self.clientOwners = res;
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: "Error fetching client owners"
                });
            });
        }

        function removeOwner(user) {
            ClientsService.removeClientOwner(self.client.client_id, user.id).then(res => {
                updateClientOwners();
            }).catch(err => {
                toaster.pop({
                    type: 'error',
                    body: "Error removing client owner"
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
                    updateClientOwners();
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
            controller: ['ClientsService', '$uibModal', 'toaster', ClientOwnersController],
            controllerAs: '$ctrl'
        };
    }

}());