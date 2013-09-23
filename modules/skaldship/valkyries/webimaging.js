/* Capture a screenshot of a URL and save it to a file using phantomjs
 *
 * (c) 2010-2013 Cisco Systems, Inc.
 */

var page = require('webpage').create(),
    system = require('system'),
    url, outputfile;

if (system.args.length <= 2) {
    console.log("Usage: webimaging.js <url> <outputfile>");
    phantom.exit();
}

url = system.args[1];
outputfile = system.args[2];

page.viewportSize = { width: 1024, height: 768 };
page.clipRect = { top: 0, left: 0, width: 1024, height: 768 };
page.timeout = 200;
page.open(url, function () {
    page.render(outputfile);
    phantom.exit();
});
