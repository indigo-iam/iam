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
        .component('groupDescription', groupDescription());

    function SetDescription($uibModalInstance, GroupsService, toaster, group) {
        var self = this;
        self.group = group;
        self.description = self.group["urn:indigo-dc:scim:schemas:IndigoGroup"].description;
        self.enabled = true;
        self.cancel = cancel;
        self.submit = submit;


        function cancel() {
            $uibModalInstance.dismiss("cancel");
        }

        function submit() {
            self.enabled = false;

            var g = {
                id: self.group.id,
                description: self.description
            };

            var handleSuccess = function (res) {
                $uibModalInstance.close(res);
            };

            var handleError = function (res) {
                toaster.pop({
                    type: 'error',
                    body: res.error
                });
                self.enabled = true;
            };

            GroupsService.setGroupDescription(g).then(handleSuccess, handleError);
        }
    }

    GroupDescriptionController.$inject = ['Utils', '$uibModal', 'toaster'];

    function GroupDescriptionController(Utils, $uibModal, toaster) {
        var self = this;

        self.$onInit = $onInit;
        self.groupDescription = groupDescription;
        self.changeDescription = changeDescription;

        function $onInit() {
            self.voAdmin = Utils.isAdmin();

        }

        function groupDescription() {
            if (self.group["urn:indigo-dc:scim:schemas:IndigoGroup"]) {
                return self.group["urn:indigo-dc:scim:schemas:IndigoGroup"].description;
            }

            return undefined;
        }

        function changeDescription() {

            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/group/set-group-description.dialog.html',
                controller: SetDescription,
                controllerAs: '$ctrl',
                resolve: { group: function () { return self.group; } }
            });

            var handleSuccess = function (res) {
                self.group["urn:indigo-dc:scim:schemas:IndigoGroup"].description = res.data.description;
                toaster.pop({
                    type: 'success',
                    body: "Description changed"
                });
                return res;
            };

            var handleError = function (res) {

            };

            modalInstance.result.then(handleSuccess, handleError);
        }
    }

    function groupDescription() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/group/group.description.component.html",
            bindings: { group: '=' },
            controller: GroupDescriptionController,
            controllerAs: '$ctrl'
        };
    }

}());