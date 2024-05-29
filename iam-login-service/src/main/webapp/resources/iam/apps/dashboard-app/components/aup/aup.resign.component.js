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

    function ResignModalController($scope, $uibModalInstance, toaster, AupService, user) {
        var self = this;
        self.enabled = true;
        self.user = user;

        self.cancel = function() {
            $uibModalInstance.close('Cancelled');
        };

        self.submit = function() {
            self.error = undefined;
            self.enabled = false;
            AupService.resignAup()
                .then(function(res) {
                    $uibModalInstance.close('AUP signature re-signed succesfully');
                    self.enabled = true;
                }, function(res) {
                    self.error = res.data.error;
                    self.enabled = true;
                    toaster.pop({ type: 'error', body: self.error});
                });
        };
    }

    function AupResignController($scope, $uibModal, toaster) {
        var self = this;
        self.enabled = true;

        self.isMe = function () {
            return self.userCtrl.isMe();
        };

        self.openSignAUPModal = function() {
        var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/templates/home/resignAup.html',
                controller: ResignModalController,
                controllerAs: 'resignModalCtrl',
                resolve: {user: function() { return self.user; }}
            });
    
        modalInstance.result.then(function(msg) {
                toaster.pop({type: 'success', body: msg});
            }, function () {
                console.log('Re-sign AUP modal dismissed at: ' + new Date());
            });
        };        
    }


    angular.module('dashboardApp').component('aupResign', {
        templateUrl: '/resources/iam/apps/dashboard-app/components/aup/aup.resign.component.html',
        bindings: {
            user: '<'
        },
        controller: [
            '$rootScope', '$uibModal', 'toaster', 'AupService', AupResignController
        ]
    });
})();