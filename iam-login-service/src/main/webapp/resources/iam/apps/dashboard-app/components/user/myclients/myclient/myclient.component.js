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

    function MyClientController($location, ClientRegistrationService, toaster, $uibModal) {
        var self = this;

        self.cancel = cancel;
        self.resetVal = resetVal;
        self.saveClient = saveClient;
        self.deleteClient = deleteClient;

        self.$onInit = function () {
            console.log('MyClientController.self', self);
            if (self.newClient) {
                self.clientVal = angular.copy(self.newClient);
                self.client = self.clientVal;
            } else {
                self.clientVal = angular.copy(self.client);
            }
        };

        function resetVal() {
            self.clientVal = angular.copy(self.client);
            toaster.pop({
                type: 'success',
                body: 'Client has been reset to the last loaded information'
            });
        }

        function cancel() {
            $location.path('/home/clients');
        }

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

        function registerClient() {
            return ClientRegistrationService.registerClient(self.clientVal).then(res => {
                handleSuccess(res);
                $location.path('/home/clients');
                return res;
            }).catch(handleError);
        }

        function saveClient() {
            if (self.newClient) {
                return registerClient();
            } else {
                return ClientRegistrationService.saveClient(self.clientVal.client_id, self.clientVal)
                    .then(handleSuccess).catch(handleError);
            }
        }

        function deleteClient() {
            var modalInstance = $uibModal.open({
                component: 'confirmclientremoval',
                resolve: {
                    client: function () {
                        return self.clientVal;
                    },
                    dynReg: function () {
                        return true;
                    }
                }
            });

            modalInstance.result.then(function (res) {
                toaster.pop({
                    type: 'success',
                    body: 'Client deleted!'
                });
                $location.path('/home/clients');
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
        .component('myClient', myClient());


    function myClient() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/user/myclients/myclient/myclient.component.html",
            bindings: {
                client: '=',
                systemScopes: '<',
                newClient: '<'
            },
            controller: ['$location', 'ClientRegistrationService', 'toaster', '$uibModal', MyClientController],
            controllerAs: '$ctrl'
        };
    }

}());