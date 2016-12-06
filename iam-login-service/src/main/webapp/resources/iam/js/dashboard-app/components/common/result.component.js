(function() {
  'use strict';

  function ResultController() {
    var self = this;

    self.$onInit = function() { console.log('ResultController onInit'); };
  }

  angular.module('dashboardApp').component('result', {
    templateUrl:
        '/resources/iam/js/dashboard-app/components/common/result.component.html',
    bindings: {result: '<'},
    controller: ResultController
  });
})();