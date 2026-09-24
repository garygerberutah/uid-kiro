// Serve a single-page application from S3 without a server.
//
// The portal is one bundle. Every route it has -- /sife, /sife/users/all,
// /sife/divisions -- is a path React resolves in the browser, and none of them
// is an object in the bucket. Asking S3 for /sife/users/all returns 404, so a
// deep link, a refresh and a bookmark all fail while the same page reached by
// clicking works. This rewrites those requests to the one object that does
// exist and lets the router take it from there.
//
// The test is "does the last segment look like a file". A trailing slash, or a
// leaf with no dot, is a route; anything else -- /assets/index-DG74JczI.js,
// /favicon.ico, /silent-renew.html -- is a real object and is left alone.
//
// **Attach this to the default cache behaviour only.** The portal's API lives
// on the same hostname under /portal/* and /licensee/*, which are extensionless
// and would every one of them be rewritten to /index.html. Those paths belong
// to cache behaviours pointing at the API origin, which this function never
// sees. Attaching it to a behaviour that does reach the API turns every API
// call into the HTML of the home page, with a 200 status.
//
// Runtime is cloudfront-js-2.0: ES5-ish, no async, no network, sub-millisecond.
// Keep it that way. Anything that needs more belongs in Lambda@Edge, which
// costs a request round trip on every viewer request.

function handler(event) {
  var request = event.request;
  var uri = request.uri;
  var leaf = uri.substring(uri.lastIndexOf('/') + 1);

  if (uri.charAt(uri.length - 1) === '/' || leaf.indexOf('.') === -1) {
    request.uri = '/index.html';
  }

  return request;
}
