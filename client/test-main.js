var tests = ['/base/client/tests/rz_config.js'];
var TEST_REGEXP = /\/(spec|test)_.*\.js$/i;

// Get a list of all the test files to include
Object.keys(window.__karma__.files).forEach(function(file) {
  "use strict";
  if (TEST_REGEXP.test(file)) {
    tests.push(file);
  }
});
var lib_path = '/base/res/client/lib/';

require.config({
  // Karma serves files under /base, which is the basePath from your config file
  baseUrl: '/base/client',

    shim: {
        'socketio': { exports: 'io' },
        'Bacon': {
            deps: ['jquery'],
            exports: 'Bacon',
        }
    },

    paths: {
        util: '/base/client/util',

        // libraries paths
        autocomplete: lib_path + 'autocomplete',
        Bacon: lib_path + 'Bacon',
        caret: lib_path + 'caret',
        cola: lib_path + 'cola',
        domain_types: 'res/local/js/domain_types',
        d3: lib_path + 'd3/d3',
        feedback: lib_path + 'feedback',
        FileSaver: lib_path + 'FileSaver',
        html2canvas: lib_path + 'html2canvas',
        jquery: lib_path + 'jquery',
        socketio: lib_path + 'socket.io/socket.io.min_0.9.10',
        underscore: lib_path + 'underscore',

        // figure out how to make this dynamic for testing later
        domain_types: '/base/client/tests/domain_types'
    },

  // dynamically load all test files
  deps: tests,

  // we have to kickoff jasmine, as it is asynchronous
  callback: window.__karma__.start
});
