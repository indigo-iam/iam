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

  angular.module('iam-login-app', ['ui.bootstrap'])
      .controller(
          'idp-selection',
          [
            '$scope', '$http', '$uibModalInstance', '$log', '$window',
			'$timeout',
            function($scope, $http, $uibModalInstance, $log, $window, $timeout) {

              $scope.ok = function() {
                $window.location.href =
                    '/saml/login?idp=' + $scope.idpSelected.entityId;
              };

              $scope.cancel = function() { $uibModalInstance.close(); };

			  $scope.reset = function(){
				  $scope.idpSelected = null;
				  $timeout(function(){
					  $window.document.getElementById("idp-selection-input").focus();
				  },0);
			  };

              $scope.lookupIdp = function(val) {

                var result =
                    $http.get('/saml/idps', {params: {q: val}})
                        .then(function(response) { return response.data; });

                return result;
              };
            }
          ])
      .controller('idp-selection-modal-ctrl', [
        '$scope', '$uibModal',
        function($scope, $uibModal) {

          $scope.open = function() {
            $uibModal.open({
              templateUrl:
                  '/resources/iam/template/idpSelectionModalContent.html',
              controller: 'idp-selection',
              size: 'lg',
              animation: true
            });
          };
        }
      ]);
})();