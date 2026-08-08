function handler(event) {
  var request = event.request;

  if (request.uri === '/api/v2' || request.uri.indexOf('/api/v2/') === 0) {
    return request;
  }

  if (request.uri === '/api' || request.uri === '/api/') {
    request.uri = '/api/v1' + (request.uri === '/api/' ? '/' : '');
  } else if (request.uri.indexOf('/api/') === 0) {
    request.uri = '/api/v1' + request.uri.substring(4);
  }

  return request;
}
