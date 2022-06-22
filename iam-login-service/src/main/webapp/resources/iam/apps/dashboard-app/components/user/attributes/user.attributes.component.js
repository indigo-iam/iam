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

    angular
        .module('dashboardApp')
        .component('userAttributes', userAttributes());

    function UserAttributesController(toaster, $uibModal, AttributesService, Utils, $state) {
        var self = this;

        self.hasAttributes = hasAttributes;
        self.isVoAdmin = isVoAdmin;
        self.setAttribute = setAttribute;
        self.removeAttribute = removeAttribute;

        self.$onInit = function () {
            console.log('UserAttributesController onInit');
            console.log('UserAttributesController self.attributes: ', self.attributes);
        };

        function hasAttributes() {
            
            if (self.attributes) {
                return self.attributes.length > 0;
            }

            return false;
        }

        function isVoAdmin(){
            return Utils.isAdmin();
        }

        function removeAttribute(attr){
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/attributes/remove-attribute.dialog.html',
                controller: RemoveUserAttribute,
                controllerAs: '$ctrl',
                resolve: {
                    user: self.user,
                    attr: attr
                }
            });

            modalInstance.result.then(function (r) {
                $state.reload();
                toaster.pop({
                    type: 'success',
                    body: 'Attribute removed'
                });
            }).catch(function (r) {
                if (r != 'escape key press' && r != 'Dismissed') {
                    $state.reload();
                    toaster.pop({
                        type: 'error',
                        body: 'Error removing attribute'
                    });
                }
            });
        }

        function setAttribute(){
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/attributes/set-attribute.dialog.html',
                controller: SetUserAttribute,
                controllerAs: '$ctrl',
                resolve: {
                    user: self.user
                }
            });

            modalInstance.result.then(function (r) {
                $state.reload();
                toaster.pop({
                    type: 'success',
                    body: 'Attribute set'
                });
            }).catch(function (r) {
                if (r != 'escape key press' && r != 'Dismissed') {
                    $state.reload();
                    toaster.pop({
                        type: 'error',
                        body: 'Error setting attribute'
                    });
                }
            });
        }

    }

    function RemoveUserAttribute(AttributesService, $uibModalInstance, user, attr) {
        var self = this;

        self.user = user;
        self.attr= attr;
        self.enabled = true;
        
        self.removeAttribute = removeAttribute;
        self.cancel = cancel;

        function cancel(){
            $uibModalInstance.dismiss('Dismissed');
        }

        function handleSuccess(res) {
            $uibModalInstance.close(res);
        }

        function handleFailure(res) {
            if (res.data) {
                self.error = res.data.error;
            } else {
                self.error = res.statusText;
            }
        }

        function removeAttribute() {
            self.error = undefined;
            return AttributesService.deleteAccountAttribute(self.user.id, self.attr).then(handleSuccess).catch(handleFailure);
        }
    }

    function SetUserAttribute(AttributesService, $uibModalInstance, user) {

        var self = this;

        self.user = user;
        self.enabled = true;
        self.attrVal = {
            name: "",
            value: ""
        };

        self.setAttribute = setAttribute;
        self.cancel = cancel;

        function cancel(){
            $uibModalInstance.dismiss('Dismissed');
        }

        function handleSuccess(res) {
            $uibModalInstance.close(res);
        }

        function handleFailure(res) {
            if (res.data) {
                self.error = res.data.error;
            } else {
                self.error = res.statusText;
            }
        }

        function setAttribute() {
            self.error = undefined;
            return AttributesService.setAccountAttribute(self.user.id, self.attrVal).then(handleSuccess).catch(handleFailure);
        }
    }

    function userAttributes() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/user/attributes/user.attributes.component.html",
            bindings: {
                user: "<",
                attributes: "="
            },
            controller: ['toaster', '$uibModal', 'AttributesService', 'Utils', '$state',
                UserAttributesController
            ],
            controllerAs: '$ctrl'
        };
    }

})();