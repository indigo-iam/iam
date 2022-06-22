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


    function ClientController(ClientsService, toaster, $uibModal, $location) {
        var self = this;

        self.resetVal = resetVal;
        self.saveClient = saveClient;
        self.loadClient = loadClient;
        self.deleteClient = deleteClient;
        self.cancel = cancel;

        self.$onInit = function () {
            if (self.newClient) {
                self.clientVal = angular.copy(self.newClient);
                self.client = self.clientVal;
            } else {
                self.clientVal = angular.copy(self.client);
            }
            console.debug('ClientController.self', self);
        };

        function resetVal() {
            self.clientVal = angular.copy(self.client);
            toaster.pop({
                type: 'success',
                body: 'Client has been reset to the last saved information'
            });
        }

        function loadClient() {
            ClientsService.retrieveClient(self.client.client_id).then(function (data) {
                console.debug("Loaded client", data);
                self.client = data;
                self.clientVal = angular.copy(self.client);
            }).catch(function (res) {
                console.debug("Error retrieving client!", res);
                toaster.pop({
                    type: 'error',
                    body: 'Error retrieving client!'
                });
            });
        }

        function saveClient() {


            function handleSuccess(res) {
                self.client = res;
                self.clientVal = angular.copy(self.client);

                toaster.pop({
                    type: 'success',
                    body: 'Client saved!'
                });
                return res;
            }

            function handleError(res) {
                console.debug("Error saving client!", res);
                var errorMsg = 'Error saving client!';

                if (res.data && res.data.error) {
                    errorMsg = "Error saving client: " + res.data.error;
                }

                toaster.pop({
                    type: 'error',
                    body: errorMsg
                });
            }

            if (self.newClient) {
                return ClientsService.createClient(self.clientVal).then(res => {
                    toaster.pop({
                        type: 'success',
                        body: 'Client saved!'
                    });
                    $location.path('/clients');
                }).catch(handleError);
            } else {

                return ClientsService.saveClient(self.clientVal.client_id, self.clientVal).then(handleSuccess)
                    .catch(handleError);

            }
        }

        function cancel() {
            $location.path('/clients');
        }

        function deleteClient() {
            var modalInstance = $uibModal.open({
                component: 'confirmclientremoval',
                resolve: {
                    client: function () {
                        return self.clientVal;
                    }
                }
            });

            modalInstance.result.then(function (res) {
                toaster.pop({
                    type: 'success',
                    body: 'Client deleted!'
                });
                $location.path('/clients');
            }, function (res) {
                if (res !== 'cancel') {
                    toaster.pop({
                        type: 'error',
                        body: 'Error deleting client'
                    });
                }
            });
        }
    }

    angular
        .module('dashboardApp')
        .component('client', client());


    function client() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/client.component.html",
            bindings: {
                client: '<',
                systemScopes: '<',
                newClient: '<',
                clientOwners: '<'
            },
            controller: ['ClientsService', 'toaster', '$uibModal', '$location', ClientController],
            controllerAs: '$ctrl'
        };
    }

}());