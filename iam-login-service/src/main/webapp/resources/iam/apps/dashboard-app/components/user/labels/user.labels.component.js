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
        .component('userLabels', userLabels());


    function UserLabelsController(toaster, $uibModal, LabelsService) {
        var self = this;

        self.labelName = labelName;

        self.$onInit = function () {
            console.log('UserLabelsController onInit');
            console.log('UserLabelsController self.labels: ', self.labels);
        };

        function labelName(label) {
            if (label.prefix) {
                return label.prefix + "/" + label.name;
            }

            return label.name;
        }
    }

    function userLabels() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/user/labels/user.labels.component.html",
            bindings: {
                user: "<",
                labels: "="
            },
            controller: ['toaster', '$uibModal', 'LabelsService',
                UserLabelsController
            ],
            controllerAs: '$ctrl'
        };
    }

})();