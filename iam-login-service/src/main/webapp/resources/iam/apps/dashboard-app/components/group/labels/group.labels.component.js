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
        .component('groupLabels', groupLabels());


    function groupLabels() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/group/labels/group.labels.component.html",
            bindings: {
                group: "<",
                labels: "<"
            },
            controller: ['toaster', '$uibModal', '$state', 'Utils', 'LabelsService', GroupLabelsController],
            controllerAs: '$ctrl'
        };
    }

    function GroupLabelsController(toaster, $uibModal, $state, Utils, LabelsService) {
        var self = this;

        self.setLabel = setLabel;
        self.isAdmin = isAdmin;
        self.labelName = labelName;
        self.deleteLabel = deleteLabel;

        self.$onInit = function () {
            console.log('GroupLabelsController.self', self);
        };

        function isAdmin() {
            return Utils.isAdmin();
        }

        function labelName(label) {
            if (label.prefix) {
                return label.prefix + "/" + label.name;
            }

            return label.name;
        }

        function deleteLabel(label) {
            LabelsService.deleteGroupLabel(self.group.id, label).then(
                function (res) {
                    $state.reload();
                    toaster.pop({
                        type: 'success',
                        body: 'Label deleted'
                    });
                }).catch(
                    function (res) {
                        $state.reload();
                        if (res.data) {
                            toaster.pop({
                                type: 'error',
                                body: res.data.error
                            });
                        } else {
                            toaster.pop({
                                type: 'error',
                                body: 'Error deleting label'
                            });
                        }
                    });
        }

        function setLabel() {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/group/labels/set-group-label.dialog.html',
                controller: SetGroupLabel,
                controllerAs: '$ctrl',
                resolve: {
                    group: self.group
                }
            });

            modalInstance.result.then(function (r) {
                $state.reload();
                toaster.pop({
                    type: 'success',
                    body: 'Label set'
                });
            }).catch(function (r) {
                if (r != 'escape key press' && r != 'Dismissed') {
                    $state.reload();
                    toaster.pop({
                        type: 'error',
                        body: 'Error setting label'
                    });
                }
            });
        }

    }

    function SetGroupLabel(LabelsService, $uibModalInstance, group) {

        var self = this;

        self.group = group;
        self.enabled = true;
        self.labelVal = {
            name: "",
            value: ""
        };

        self.setLabel = setLabel;

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };

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

        function setLabel() {
            self.error = undefined;
            return LabelsService.setGroupLabel(self.group.id, self.labelVal).then(handleSuccess).catch(handleFailure);
        }
    }

}());