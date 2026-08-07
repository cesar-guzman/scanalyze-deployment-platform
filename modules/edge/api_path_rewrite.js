function handler(event) {
  var request = event.request;

  if (request.uri === '/api' || request.uri === '/api/') {
    request.uri = '/';
  } else if (request.uri.indexOf('/api/') === 0) {
    request.uri = request.uri.substring(4);
  }

  return request;
}
