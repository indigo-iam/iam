'use strict';

angular.module('dashboardApp').controller('GroupController', GroupController);

GroupController.$inject = [ '$state', 'scimFactory' ];

function GroupController($state, scimFactory) {

	var group = this;

	group.id = $state.params.id;
	group.data = [];

	scimFactory.getGroup(group.id).then(
			function(response) {

				console.log(response.data);
				group.data = response.data;
				group.data.members = $filter('orderBy')(group.data.members,
						"display", false);

			}, function(error) {
				$state.go("error", {
					"error" : error
				});
			});

	group.removeMemberFromList = removeMemberFromList;

	function removeMemberFromList(user) {

		var i = group.data.members.indexOf(user);
		group.data.members.splice(i, 1);
	}

	group.deleteMember = deleteMember;

	function deleteMember(user) {

		scimFactory.removeUserFromGroup(group.id, user.value, user.$ref,
				user.display).then(function(response) {
			console.log("Deleted: ", user.display);
			group.removeMemberFromList(user);
		}, function(error) {
			$state.go("error", {
				"error" : error
			});
		});
	}
}