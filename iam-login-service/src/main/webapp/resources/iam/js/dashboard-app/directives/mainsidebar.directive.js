angular.module('dashboardApp').directive('mainsidebar', function() {
	return {
		restrict : 'E',
		templateUrl : '/resources/iam/template/dashboard/nav.html',
		compile : function(tElement, tAttrs, transclude) {
		}
	};
});