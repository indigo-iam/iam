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
'use strict';

angular.module('dashboardApp').controller('EditMeController',
		EditMeController);

EditMeController.$inject = [ '$scope', '$rootScope', '$state', '$uibModalInstance',
		'Utils', 'scimFactory', 'user' ];

function EditMeController($scope, $rootScope, $state, $uibModalInstance, Utils,
		scimFactory, user) {

	var editMeCtrl = this;

	editMeCtrl.oUser = user;
	editMeCtrl.id = user.id;

	editMeCtrl.submit = submit;
	editMeCtrl.reset = reset;
	editMeCtrl.dismiss = dismiss;
	editMeCtrl.isSubmitDisabled = isSubmitDisabled;

	editMeCtrl.reset();

	function submit() {

		editMeCtrl.enabled = false;

		var operations = [];
		
		// remove picture if it's dirty and empty
		if ($scope.userUpdateForm.picture.$dirty && !editMeCtrl.eUser.picture) {
			operations.push({
				op: "remove",
				value: {
					photos: editMeCtrl.oUser.photos
				}
			});
		}

		if ($scope.userUpdateForm.name.$dirty || $scope.userUpdateForm.surname.$dirty) {
			
			operations.push({
				op: "replace",
				value: {
					displayName: editMeCtrl.eUser.name + " " + editMeCtrl.eUser.surname,
					name: {
						givenName : editMeCtrl.eUser.name,
						familyName : editMeCtrl.eUser.surname,
						middleName : ""
					}
				}
			});
		}
		if ($scope.userUpdateForm.email.$dirty) {
			
			operations.push({
				op: "replace",
				value: {
					emails: [ {
						type : "work",
						value : editMeCtrl.eUser.email,
						primary : true
					} ]
				}
			});
		}
		if ($scope.userUpdateForm.picture.$dirty) {

			operations.push({
				op: "replace",
				value: {
					photos: [{
						type : "photo",
						value : editMeCtrl.eUser.picture
					}]
				}
			});
		}

		console.info("Operations ... ", operations);

		scimFactory.updateMe(operations).then(
			function(response) {

				$rootScope.reloadInfo();

				$uibModalInstance.close(response);
				editMeCtrl.enabled = true;
			},
			function(error) {
				$scope.operationResult = Utils.buildErrorOperationResult(error);
				editMeCtrl.enabled = true;
			});
	}

	function reset() {
		editMeCtrl.eUser = {
				name : editMeCtrl.oUser.name.givenName,
				surname : editMeCtrl.oUser.name.familyName,
				picture : editMeCtrl.oUser.photos ? editMeCtrl.oUser.photos[0].value : "",
				email : editMeCtrl.oUser.emails[0].value,
			};
		if ($scope.userUpdateForm) {
			$scope.userUpdateForm.$setPristine();
		}
		editMeCtrl.enabled = true;
	}

	function dismiss() {
		$uibModalInstance.dismiss('Cancel');
	}

	function isSubmitDisabled() {
		return !editMeCtrl.enabled 
				|| !$scope.userUpdateForm.$dirty 
				|| $scope.userUpdateForm.name.$invalid
				|| $scope.userUpdateForm.surname.$invalid
				|| $scope.userUpdateForm.email.$invalid
				|| $scope.userUpdateForm.picture.$invalid;
	}
}