'use strict';

angular.module('dashboardApp').controller('EditUserController',
		EditUserController);

EditUserController.$inject = [ '$scope', '$state', '$uibModalInstance',
		'Utils', 'scimFactory', 'user' ];

function EditUserController($scope, $state, $uibModalInstance, Utils,
		scimFactory, user) {

	var editUserCtrl = this;
	
	console.info("Editing user ", user);

	editUserCtrl.id = user.id;

	editUserCtrl.userToEdit = {
		name : user.name.givenName,
		surname: user.name.familyName,
		username : user.userName,
		email : user.emails[0].value,
		picture : user.picture == undefined ? "" : user.picture
	};

	console.info("Copied user ", editUserCtrl.userToEdit);

	editUserCtrl.submit = submit;
	editUserCtrl.reset = reset;
	editUserCtrl.dismiss = dismiss;
	editUserCtrl.isSubmitDisabled = isSubmitDisabled;

	editUserCtrl.reset();

	function submit() {

		editUserCtrl.enabled = false;

		var scimUser = {};

		console.info($scope.userUpdateForm.name.$pristine);
		console.info($scope.userUpdateForm.surname.$pristine);
		console.info($scope.userUpdateForm.email.$pristine);
		console.info($scope.userUpdateForm.username.$pristine);
		console.info($scope.userUpdateForm.picture.$pristine);

		if ($scope.userUpdateForm.name.$dirty || $scope.userUpdateForm.surname.$dirty) {
			scimUser.displayName = editUserCtrl.user.name + " "
					+ editUserCtrl.user.surname;
			scimUser.name = {
					givenName : editUserCtrl.user.name,
					familyName : editUserCtrl.user.surname,
					middleName : ""
			};
		}
		if ($scope.userUpdateForm.email.$dirty) {
			scimUser.emails = [ {
				type : "work",
				value : editUserCtrl.user.email,
				primary : true
			} ];
		}
		if ($scope.userUpdateForm.username.$dirty) {
			scimUser.userName = editUserCtrl.user.username;
		}
		if ($scope.userUpdateForm.picture.$dirty) {
			scimUser.picture = editUserCtrl.user.picture;
		}

		console.info("Edited user ... ", scimUser);

		scimFactory.updateUser(user.id, scimUser).then(
			function(response) {
				$uibModalInstance.close(response);
				editUserCtrl.enabled = true;
			},
			function(error) {
				$scope.operationResult = Utils.buildErrorOperationResult(error);
				editUserCtrl.enabled = true;
			});
	}

	function reset() {
		editUserCtrl.user = angular.copy(editUserCtrl.userToEdit);
		console.info(editUserCtrl.user);
		if ($scope.userUpdateForm) {
			$scope.userUpdateForm.$setPristine();
		}
		editUserCtrl.enabled = true;
	}

	function dismiss() {
		$uibModalInstance.dismiss('Cancel');
	}

	function isSubmitDisabled() {
		console.log(!editUserCtrl.enabled, !$scope.userUpdateForm.$dirty, 
				$scope.userUpdateForm.name.$invalid, $scope.userUpdateForm.surname.$invalid, 
				$scope.userUpdateForm.email.$invalid, $scope.userUpdateForm.username.$invalid, 
				$scope.userUpdateForm.picture.$invalid);
		return !editUserCtrl.enabled 
				|| !$scope.userUpdateForm.$dirty 
				|| $scope.userUpdateForm.name.$invalid
				|| $scope.userUpdateForm.surname.$invalid
				|| $scope.userUpdateForm.email.$invalid
				|| $scope.userUpdateForm.username.$invalid
				|| $scope.userUpdateForm.picture.$invalid;
	}
}