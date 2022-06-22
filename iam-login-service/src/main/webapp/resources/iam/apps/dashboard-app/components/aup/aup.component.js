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

    function DeleteAupController($scope, $uibModalInstance, AupService) {
        var self = this;
        self.enabled = true;

        self.cancel = function() {
            $uibModalInstance.close();
        };

        self.doDeleteAup = function() {
            self.error = undefined;
            self.enabled = false;
            AupService.deleteAup()
                .then(function(res) {
                    $uibModalInstance.close('AUP deleted succesfully');
                    self.enabled = true;
                }).catch(function(res) {
                    self.error = res.data.error;
                    self.enabled = true;
                });
        };
    }

    function SignAupController($scope, $uibModalInstance, AupService) {
        var self = this;
        self.enabled = true;

        self.cancel = function() {
            $uibModalInstance.close();
        };

        self.doTouchAup = function() {
            self.error = undefined;
            self.enabled = false;
            AupService.touchAup()
                .then(function(res) {
                    $uibModalInstance.close('AUP signature requested succesfully');
                    self.enabled = true;
                }).catch(function(res) {
                    self.error = res.data.error;
                    self.enabled = true;
                });
        };
    }

    function EditAupController($scope, $uibModalInstance, AupService, aup) {
        var self = this;
        self.enabled = true;
        self.aup = aup;
        console.log("EditAupController self.aup: ", self.aup);

        self.cancel = function() {
            $uibModalInstance.close();
        };

        self.reset = function() {
            self.aupVal = {
                url: self.aup.url,
                signatureValidityInDays: self.aup.signatureValidityInDays
            };
        };

        self.reset();

        self.doSaveAup = function() {
            self.error = undefined;
            self.enabled = false;
            AupService.updateAup(self.aupVal)
                .then(function(res) {
                    $uibModalInstance.close('AUP updated succesfully');
                    self.enabled = true;
                }).catch(function(res) {
                    self.error = res.data.error;
                    self.enabled = true;
                });
        };
    }

    function CreateAupController($scope, $uibModalInstance, AupService) {
        var self = this;
        self.enabled = true;

        self.cancel = function() {
            $uibModalInstance.close();
        };

        self.reset = function() {
            self.aupVal = {
                url: "",
                signatureValidityInDays: 0
            };
        };

        self.reset();

        self.doCreateAup = function() {
            self.error = undefined;
            self.enabled = false;
            AupService.createAup(self.aupVal)
                .then(function(res) {
                    $uibModalInstance.close('AUP created succesfully');
                    self.enabled = true;
                }).catch(function(res) {
                    self.error = res.data.error;
                    self.enabled = true;
                });
        };
    }

    function AupController($rootScope, $uibModal, toaster, AupService) {
        var self = this;
        self.$onInit = function() {
            console.log('AupController onInit');
            self.loaded = true;
            console.info('Aup: ', self.aup);
        };

        self.handleSuccess = function(msg) {
            if (msg != null) {
                toaster.pop({
                    type: 'success',
                    body: msg
                });
            }
            self.aup = AupService.getAup().then(function(res) {
                self.aup = res;
            });
        };

        self.openEditAupDialog = function() {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/aup/aup.edit.dialog.html',
                controller: EditAupController,
                controllerAs: '$ctrl',
                resolve: {
                    aup: function() { return self.aup.data; }
                }
            });

            modalInstance.result.then(self.handleSuccess);
        };

        self.openCreateAupDialog = function() {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/aup/aup.create.dialog.html',
                controller: CreateAupController,
                controllerAs: '$ctrl'
            });

            modalInstance.result.then(self.handleSuccess);
        };

        self.openDeleteAupDialog = function() {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/aup/aup.delete.dialog.html',
                controller: DeleteAupController,
                controllerAs: '$ctrl'
            });

            modalInstance.result.then(self.handleSuccess);
        };

        self.openSignAupDialog = function() {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/aup/aup.sign.dialog.html',
                controller: SignAupController,
                controllerAs: '$ctrl'
            });

            modalInstance.result.then(self.handleSuccess);
        };
    }

    angular.module('dashboardApp').component('aup', {
        templateUrl: '/resources/iam/apps/dashboard-app/components/aup/aup.component.html',
        bindings: {
            aup: '<'
        },
        controller: [
            '$rootScope', '$uibModal', 'toaster',
            'AupService', AupController
        ]
    });
})();