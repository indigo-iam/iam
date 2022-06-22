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

    function InputListController() {

        var self = this;

        self.addElement = addElement;
        self.removeElement = removeElement;
        self.onKeyPress = onKeyPress;

        function onKeyPress(event) {
            if (event.keyCode == 13) {
                addElement();
            }
        }
        function addElement() {
            if (!self.model) {
                self.model = [];
            }
            if (self.val) {

                var itemFound = self.model.indexOf(self.val);
                if (itemFound != -1) {
                    self.msg = "List already contains that item";
                }
                else {
                    self.model.push(self.val);
                    self.val = undefined;
                    self.msg = undefined;
                }
            }
        }

        function removeElement(item) {
            if (self.model) {
                self.model.splice(self.model.indexOf(item), 1);
            }
        }

        self.$onInit = function () {
            if (!self.model) {
                self.model = [];
            }
            self.val = undefined;
            console.debug('InputListController.self', self);
        };
    }

    angular
        .module('dashboardApp')
        .component('inputlist', inputlist());


    function inputlist() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/common/inputlist/inputlist.component.html",
            bindings: {
                id: '@',
                emptylisttext: '@',
                helptext: '@',
                placeholder: '@',
                label: '@',
                model: '=',
            },
            controller: InputListController,
            controllerAs: '$ctrl'
        };
    }

}());