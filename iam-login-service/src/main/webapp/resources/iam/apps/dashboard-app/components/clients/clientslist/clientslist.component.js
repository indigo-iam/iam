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

    function ClientsListController($filter, $uibModal, ClientsService, FindService, toaster) {
        var self = this;

        self.searchFilter = '';

        self.splitScopes = splitScopes;
        self.searchClients = searchClients;
        self.resetFilter = resetFilter;
        self.onChangePage = onChangePage;
        self.deleteClient = deleteClient;
        self.clientTrackLastUsed = getClientTrackLastUsed();
        self.getClientStatusMessage = getClientStatusMessage;

        self.$onInit = function () {
            console.debug('ClientsListController.self', self);
            self.currentPage = 1;
            self.itemsPerPage = 10;
            self.searchType = "name";
            self.totalResults = self.clients.totalResults;
        };

        function splitScopes(scopes, limit) {
            var scopeList = scopes.split(' ');
            var limitedScopeList = $filter('limitTo')(scopeList, limit);
            if (limitedScopeList.length < scopeList.length) {
                limitedScopeList.push('...');
            }
            return limitedScopeList;
        }

        function onChangePage() {
            var currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;

            if (currentOffset > self.totalResults && self.currentPage > 1) {
                self.currentPage--;
                currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;
            }

            self.searchClients(currentOffset, self.itemsPerPage).then(res => {
                self.totalResults = res.totalResults;
            });
        }

        function searchClients(startIndex, itemsPerPage) {

            if (self.searchFilter === '') {
                return ClientsService.retrieveClients(startIndex, itemsPerPage, self.searchOnlyDRClients).then(res => {
                    self.clients = res;
                    self.totalResults = res.totalResults;
                    return res;
                }).catch(err => {
                    toaster.pop({
                        type: 'error',
                        body: 'Error retrieving clients!'
                    });
                    console.error("retrieveClients failed", err);
                });
            } else {
                return ClientsService.searchClients(self.searchType, self.searchFilter, startIndex, itemsPerPage, self.searchOnlyDRClients).then(res => {
                    self.clients = res;
                    self.totalResults = res.totalResults;
                    return res;
                }).catch(err => {
                    toaster.pop({
                        type: 'error',
                        body: 'Error searching clients!'
                    });
                    console.error("Search clients failed", err);
                });
            }
        }

        function resetFilter() {
            self.searchFilter = '';
            self.onChangePage();
        }

        function deleteClient(client) {
            var modalInstance = $uibModal.open({
                component: 'confirmclientremoval',
                resolve: {
                    client: function () {
                        return client;
                    }
                }
            });

            modalInstance.result.then(function (res) {
                toaster.pop({
                    type: 'success',
                    body: 'Client deleted!'
                });
                self.totalResults--;
                onChangePage();
            }, function (res) {
                if (res !== 'cancel') {
                    toaster.pop({
                        type: 'error',
                        body: 'Error deleting client'
                    });
                }
            });
        }

        function getClientStatusMessage(client){
            FindService.findAccountByUuid(client.status_changed_by).then(function(res){
                self.clientStatusMessage = "Suspended by " + res.username + " on " + getFormatedDate(client.status_changed_on);                                            
            }).catch(function (res) {
                console.debug("Error retrieving user account!", res);
            });           
        }

        function getFormatedDate(dateToFormat){
            var dateISOString = new Date(dateToFormat).toISOString();
            var ymd = dateISOString.split('T')[0];
            //Remove milliseconds
            var time = dateISOString.split('T')[1].slice(0, -5);
            return ymd + " " + time;
        }
    }

    angular
        .module('dashboardApp')
        .component('clientslist', clientslist());

    function clientslist() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/clientslist/clientslist.component.html",
            bindings: {
                clients: "<"
            },
            controller: ['$filter', '$uibModal', 'ClientsService', 'FindService', 'toaster', ClientsListController],
            controllerAs: '$ctrl'
        };
    }

}());