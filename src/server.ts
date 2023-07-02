const fs = require('fs');
const path = require('path');
const express = require('express');
const morgan = require('morgan');
const app = express();

// The express() function returns an app object, which is the main application object in Express. The app object can be used to configure the application, such as setting the port number, loading middleware, and defining routes.

// The express.router() function returns a router object, which is a smaller, more isolated object that can be used to define routes. Router objects are often used to group related routes together.
// configuring router
const router = express.Router({
  caseSensitive: true,
  mergeParams: true,
  strict: true,
});

// required in Express when you want to parse incoming JSON requests and put the parsed data in the req.body property. This is useful when you need to access the JSON data in your routes, controllers, or other middleware.
app.use(express.json());

// this middleware can be used as path specific like especially the verify part can be tailored for that like the schema validation library like joi could be used here

app.use(
  express.urlencoded({
    extended: true,
    type: 'application/x-www-form-urlencoded',
    inflate: false,
    parameterLimit: 25,
    verify: (req: any, res: any, buf: any) => {
      const contentType = req.headers['content-type'];
      if (
        contentType !== 'application/x-www-form-urlencoded' &&
        contentType !== 'application/json'
      ) {
        throw new Error('Invalid Content-Type header');
      }

      // Check the size of the request body.
      const bodySize = buf.length;
      if (bodySize > 100000) {
        throw new Error('Request body is too large');
      }

      // Check the encoding of the request body.
      const encoding = buf.encoding;
      if (encoding !== 'utf-8') {
        throw new Error('Request body is not encoded in UTF-8');
      }

      // Check for a specific key in the request body.
      const key = 'username';
      if (!req.body.hasOwnProperty(key)) {
        throw new Error('The request body does not contain the key "username"');
      }

      const encodingSchemesAccepted = req.acceptsEncodings();

      const characterSetsAccepted = req.acceptsCharsets();

      // can use the array of values stored in the above variables to modify the below condtions for acceptsEncodings, acceptsCharsets as the variable holds the values that client is ready to accept data format in
      const acceptsLanguages = req.acceptsLanguages('en-US');
      if (acceptsLanguages) {
        // The request is expecting English (US)
        res.setHeader('Content-Language', 'en-US');
        console.log('This is in English (US)');
      }

      const acceptsEncodings = req.acceptsEncodings('gzip');
      if (acceptsEncodings) {
        // setting multiple value for the Content-Encoding header so that multiple accepted encoding schemes can be represented

        // res.append is used to set multiple value for the same header and res.setHeader() overwrites the value of a header
        res.append('Content-Encoding', 'deflate');
        res.append('Content-Encoding', 'identity');
        res.append('Content-Encoding', 'gzip');

        console.log('This is compressed with gzip');
      }

      const acceptsCharsets = req.acceptsCharsets('utf-8');
      if (acceptsCharsets) {
        // The request is expecting UTF-8
        // for sending html content in response
        res.setHeader('Content-Type', 'text/html; charset=UTF-8');
        // for sending json content in response
        res.setHeader('Content-Type', 'application/json; charset=UTF-8');

        console.log('This is in UTF-8');
      }

      try {
        JSON.parse(req.body);
        // setting a custom header field and its value
        res.setHeader('my-Custom-Header', 'My Custom Value');
      } catch (e) {
        app.emit('urlencodedMiddleWareFailed', 'This is a failure message');
        throw new Error('The request body is not a valid JSON object');
      }
      app.emit('urlencodedMiddleWarePassed', 'This is a success message');

      return true;
    },
  })
);

// triggered upon emitting of the corresponding even using app.emit()
// can use this for exception handling, db connections and many more
// You can use app.on() and app.emit() to manage concurrent requests. For example, you could use app.on() to register a listener for the 'request-received' event. Then, you could use app.emit() to emit the 'request-received' event when a new request is received. This would allow you to track the number of concurrent requests and to take action if the number of requests exceeds a certain threshold
// also we can chain one one emit inside another or can trigger specific parts of code or a function upon emit of a specific event
app.on('urlencodedMiddleWareFailed', function (message: String) {
  console.log(
    'The myCustomEvent event was emitted with the message: ' + message
  );
});
app.on('urlencodedMiddleWarePassed', function (message: String) {
  console.log(
    'The myCustomEvent event was emitted with the message: ' + message
  );
});
// calling the defined router object only for the endpoint named calendar
app.use('/calendar', router);

// This will match paths starting with /abcd and /abd:

app.use('/ab(c?)d', (req: any, res: any, next: any) => {
  next();
});
//   This will match paths starting with /abc and /xyz:

app.use(/\/abc|\/xyz/, (req: any, res: any, next: any) => {
  next();
});

//   This will match paths starting with /abcd, /xyza, /lmn, and /pqr:

app.use(['/abcd', '/xyza', /\/lmn|\/pqr/], (req: any, res: any, next: any) => {
  next();
});
// to log the http request details like method, timestamp and etc
router.use(morgan('combined'));
// invoked for any requests passed to this router
router.use(function (req: any, res: any, next: any) {
  // .. some logic here .. like any other middleware
  next();
});
// for this particular router when the path parameter contains a parameter id the below logic snippet is called
router.param('id', function (req: any, res: any, next: any, id: any) {
  console.log('CALLED ONLY ONCE');
  next();
});
// will check if both the id and page parameters are present in the URL, or if either of them is present. The value parameter of the callback function will contain the value of the parameter that is present.
app.param(['id', 'page'], (req: any, res: any, next: any, value: any) => {
  console.log('CALLED ONLY ONCE with', value);
  next();
});

router.get('/user/:id', function (req: any, res: any, next: any) {
  console.log('although this matches');
  // Few console properties, explore and use more of it
  console.error('This is an error message');
  console.warn('This is a warning message');
  next();
});
// will handle any request that ends in /events for this specific router
router.get('/events', function (req: any, res: any, next: any) {
  // ..
});

// using regex for api paths
router.get(/^\/commits\/(\w+)(?:\.\.(\w+))?$/, function (req: any, res: any) {
  var from = req.params[0];
  var to = req.params[1] || 'HEAD';
  res.send('commit range ' + from + '..' + to);
});

// using .route feature to combine apis of same path names
router
  .route('/users/:user_id')
  .all(function (req: any, res: any, next: any) {
    // runs for all HTTP verbs first
    // think of it as route specific middleware!
    next();
  })
  .get(function (req: any, res: any, next: any) {
    res.json(req.user);
  })
  .put(function (req: any, res: any, next: any) {
    // just an example of maybe updating the user
    req.user.name = req.params.name;
    // save user ... etc
    res.json(req.user);
  })
  .post(function (req: any, res: any, next: any) {
    next(new Error('not implemented'));
  })
  .delete(function (req: any, res: any, next: any) {
    next(new Error('not implemented'));
  });

router.get('/testingRes.Write/:id', function (req: any, res: any, next: any) {
  // when we want to send multiple chunks of data to the client we can use res.write also it can be called multiple times before res.end() is called which ends the connection by sending all the required response to the client, if res.end is not been called then connection to the client is not closed and remains open. it is unlike res.send which is called only once post which connection with the client gets closed.
  console.log('🚀 ~ file: server.ts:147 ~ app.get ~ req:', req.host);
  console.log('🚀 ~ file: server.ts:147 ~ app.get ~ req:', req.hostname);
  console.log('🚀 ~ file: server.ts:147 ~ app.get ~ req:', req.ip);
  console.log('🚀 ~ file: server.ts:147 ~ app.get ~ req:', req.host);
  console.log(
    '🚀 ~ file: server.ts:199 ~ app.get ~ req.params.id:',
    req.params.id
  );
  console.log('🚀 ~ file: server.ts:172 ~ req.baseUrl:', req.baseUrl);
  console.log(
    '🚀 ~ file: server.ts:228 ~ app.use ~ req.originalUrl:',
    req.originalUrl
  );
  console.log('🚀 ~ file: server.ts:231 ~ app.use ~ req.path:', req.path);
  // related to caching something
  console.log('🚀 ~ file: server.ts:234 ~ app.use ~ req.stale:', req.stale);
  console.log('🚀 ~ file: server.ts:236 ~ app.use ~ req.fresh:', req.fresh);
  // Send the first chunk of data.
  res.write('Hello, world!');

  // Send the second chunk of data.
  res.write('This is a test.');

  // End the response.
  res.end(); // or can use res.status(404).end()
});

// testing req.xhr()

app.get('/xhr', (req: any, res: any) => {
  if (req.xhr) {
    // The request is an AJAX request
    res.send('This is an AJAX request');
  } else {
    // The request is not an AJAX request
    res.send('This is not an AJAX request');
  }
});
// testing req.accepts()

app.get('/accepts', (req: any, res: any) => {
  const accepts = req.accepts('application/json');

  // testing res.locals.data~
  res.locals.data = 'data';

  if (accepts) {
    // The request is expecting JSON data
    res.send({
      name: 'Bard',
      age: 18,
    });
  } else {
    // The request is not expecting JSON data
    res.send(res.locals.data);
  }
});

// testing nested apps
// used app.use() and app.get() inside of parent app.get()
app.get('/testingNestedApps', function (req: any, res: any) {
  // Check if the headers have already been sent
  if (!res.headersSent) {
    // Set the Content-Type header
    res.setHeader('Content-Type', 'application/json');
  }
  // Add a middleware function that sets the Cache-Control header
  app.use((req: any, res: any, next: any) => {
    res.setHeader('Cache-Control', 'max-age=3600');
    next();
  });

  // setting some custom header field with values using res.append()
  app.get('/', (req: any, res: any) => {
    // Set the My-Custom-Header header to "12345"
    res.append('My-Custom-Header', '12345');
    // setting some more header fields
    res.append('Set-Cookie', 'foo=bar; Path=/; HttpOnly');
    res.append('Warning', '199 Miscellaneous warning');
    // Render the response
    res.send('Hello, world!');
  });
  // Render the response
  res.render('index');
});

// testing feature to download images

app.get('/download', (req: any, res: any) => {
  const filename = 'Anirudh-Nayak(1).jpg';
  const filepath = path.join(__dirname, filename);
  // can use both the attachment and the sendfile as above but this is better
  res.download(filepath);
});

// testing cookie implementation as the code below will store a cookie in the users browser
app.get('/cookies', (req: any, res: any) => {
  // now these cookies are returned only when the domain name and path    matches for the requested endpoint.
  res.cookie('myChocoCookie', 'value', {
    expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
    maxAge: 86400,
    // provide proper domain name else it will get rejected
    domain: req.hostname,
    // endpoint name
    path: req.originalUrl,
    secure: true,
    // note that signed feature is turned on so a verification logic might be reqd to implement
    // signed:true,
    httpOnly: true,
  });

  // can send object in place of value too like this note that options is identical to those given to res.cookie(), excluding expires and maxAge.
  res.cookie(
    'cart55',
    { items: [1, 2, 3] },
    {
      maxAge: 900000,
      domain: req.hostname,
      path: req.originalUrl,
    }
  );

  // clearing a specific cookie
  res.clearCookie('cart', { path: '/' });
  res.send('Hello, world!');
});

// testing res.redirect()

app.get('/resRedirect', (req: any, res: any) => {
  res.redirect('http://localhost:3000/res.links', 302);

  // Redirects can be relative to the current URL. For example, from `http://example.com/blog/admin/` (notice the trailing slash), the following would redirect to the URL `http://example.com/blog/admin/post/new`.
  // res.redirect('post/new')
});

// testing res.sendStatus()

app.get('/resSendStatus', (req: any, res: any) => {
  // this adds these links in the headers which is usefull for frontend to navigate to any link or page upon any action by user

  res.links({
    link1: 'http://api.example.com/users?page=2',
    linktwo: 'http://api.example.com/users?page=5',
  });
  // sends corresponding status message as response if its a valid status code else the same status code number is sent in the response
  res.sendStatus(503);
});

// testing res.format()

app.get('/resFormat', (req: any, res: any) => {
  const data = {
    name: 'John Doe',
    age: 30,
  };

  res.format({
    'application/json': () => {
      res.send(JSON.stringify(data));
    },
    'text/plain': () => {
      res.send('Hello, world!');
    },
  });
});

app.listen(3000);
