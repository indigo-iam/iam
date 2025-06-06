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

    function ClientSecretViewController($uibModal, toaster, ClientsService, data) {

        var $ctrl = this;

        $ctrl.data = data;
        $ctrl.newClient = !!data.client.clientSecret ;
        $ctrl.client = data.client

        self.clipboardSuccess = clipboardSuccess;
        self.clipboardError = clipboardError;
      
        $ctrl.ok = function() {
            $uibModalInstance.close($ctrl.selected);
        };
      
        $ctrl.closeModal = function() {
            $uibModalInstance.dismiss('cancel');
        };

        function clipboardError(event) {
            toaster.pop({
                type: 'error',
                body: 'Could not copy secret to clipboard!'
            });
        }

        function clipboardSuccess(event, source) {
            toaster.pop({
                type: 'success',
                body: 'Secret copied to clipboard!'
            });
            event.clearSelection();
            if (source === 'secret') {
                toggleSecretVisibility();
            }
        }
    };

    angular.module('dashboardApp')
        .component('ClientSecretView', ClientSecretView());

        function ClientSecretView() {
            return {
                templateUrl: "/resources/iam/apps/dashboard-app/components/clients/client/newclientsecretshow/clientsecretview.component.html",
                bindings: {
                    client: "=",
                    newClient: "<",
                    limited: '@'
                },
                controller: ['$uibModal', 'toaster', 'ClientsService', 'data', ClientSecretViewController],
                controllerAs: '$ctrl'
            };
        }

}());