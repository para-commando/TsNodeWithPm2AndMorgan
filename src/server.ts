const fs = require('fs');
const path = require('path');
const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const responseTime = require('response-time');
const jwt = require('jsonwebtoken');

// use this logic to generate a token based on the secrete key
// const token = jwt.sign(
//   { username: 'req.body.username' },
//   'process.env.JWT_SECRET',
//   { expiresIn: 3600 }
// );
// res.header('Authorization', 'Bearer ' + token);

const app = express();

app.use(responseTime({
  header: 'X-Response-Time',
},(req:any, res:any,next:any) => {
  // Do something with the response time.
  next();
}));
const authenticateToken = (req:any, res:any, next:any) => {
  const token = req.headers['Authorization'];
  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const decodedToken = jwt.decode(token, process.env.JWT_SECRET);
    req.decodedTokenData = decodedToken;
    next();
  } catch (error:any) {
    return res.status(401).send(error.message);
  }
};

app.use(authenticateToken);

app.use(helmet({

  cors: {
    // The origin directive specifies the origins that are allowed to make requests to the server. In this case, the directive is set to *, which means that any origin is allowed to make requests to the server.
    origin: ["*"],
    // The methods directive specifies the methods that are allowed for cross-origin requests. In this case, the directive is set to GET, POST, PUT, and DELETE, which means that these methods are allowed for cross-origin requests.
    methods: ["GET", "POST", "PUT", "DELETE"],
  },
  // The xssFilter option uses the X-XSS-Protection header to block XSS attacks. This header tells the browser to block any attempts to inject malicious code into the page. XSS attacks are a type of security vulnerability that can be used to inject malicious code into a web page. This malicious code can then be executed by the victim's browser, which can lead to a variety of problems, such as stealing the victim's personal information or taking control of their computer
  xssFilter: true,
  // The nosniff property is used to mitigate MIME type sniffing attacks. MIME type sniffing is a technique that can be used to trick a browser into loading a resource as a different type than it actually is. This can be used to exploit vulnerabilities in browsers or to deliver malicious content to users.
  nosniff: true,
  // used to configure the HTTP Strict Transport Security (HSTS) header. HSTS is a security header that tells browsers to only connect to your website over HTTPS. This can help to protect your website from man-in-the-middle attacks.

// The maxAge property specifies the amount of time (in seconds) that the browser should remember the HSTS header. The default value is 31536000 seconds (one year).

// The includeSubDomains property specifies whether the HSTS header should apply to subdomains of your website. The default value is false.

// Setting maxAge to a high value and includeSubDomains to true is a good security practice that can help to protect your website from man-in-the-middle attacks.
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
  },
  contentSecurityPolicy: {
    // This directive specifies the default source for loading resources (such as scripts, stylesheets, images) when no other directive explicitly specifies a source. In this case, 'self' allows resources to be loaded from the same domain (the server itself), and 'https:' allows loading resources from any HTTPS source.
    defaultSrc: ["'self'", 'https:'],
    // This directive specifies the valid sources for making network requests or connections. 'self' allows requests to be made to the same domain (the server itself), and 'https:' allows requests to be made to any HTTPS source.
    connectSrc: ["'self'", 'https:'],
    // This directive enables the browser to automatically upgrade HTTP requests to HTTPS. It instructs the browser to replace any insecure (HTTP) requests with secure (HTTPS) requests.
    upgradeInsecureRequests: true,
    // This directive configures the X-Frame-Options header, which helps prevent clickjacking attacks by specifying whether a page can be displayed within an iframe. In this case, the disable option is set to true, disabling the X-Frame-Options header.
    frameGuard: {
      disable: true,
    },
    // default-src: This directive sets the default source for loading resources if no other directive explicitly specifies a source. In this case, 'self' allows resources to be loaded from the same domain (the server itself), and 'https:' allows loading resources from any HTTPS source.

    // img-src: This directive specifies valid sources for loading images. In this example, * allows loading images from any source, and data: allows inline data URIs for images.

    //  style-src: This directive specifies valid sources for loading stylesheets. 'self' allows loading stylesheets from the same domain (the server itself), 'https:' allows loading stylesheets from any HTTPS source, and 'unsafe-inline' allows inline styles to be applied.

    // script-src: This directive specifies valid sources for loading scripts. 'self' allows loading scripts from the same domain (the server itself), 'https:' allows loading scripts from any HTTPS source, 'unsafe-inline' allows inline scripts to be executed, and 'unsafe-eval' allows the use of eval() and similar dynamic code execution.

    // font-src: This directive specifies valid sources for loading fonts. 'self' allows loading fonts from the same domain (the server itself), 'https:' allows loading fonts from any HTTPS source, and data: allows inline data URIs for fonts.


    policy: "default-src 'self' https:; img-src * data:; style-src 'self' https: 'unsafe-inline'; script-src 'self' https: 'unsafe-inline' 'unsafe-eval'; font-src 'self' https: data:;",
  },
  //crossOriginEmbedderPolicy property in the Helmet middleware code is used to configure the Cross-Origin Embedder Policy (COEP) header. COEP is a security header that can help to prevent cross-site scripting (XSS) attacks.

// The policy property specifies the policy that should be used for COEP. The value of require-corp means that iframes from other origins can only be embedded in your website if they are loaded over HTTPS and if they have a valid Content-Security-Policy header.

// Setting the policy property to require-corp is a good security practice that can help to protect your website from XSS attacks.


  crossOriginEmbedderPolicy: {
    policy: "require-corp",
  },
//   The crossOriginOpenerPolicy header is used to control the behavior of the window or browsing context when navigating across different origins. The same-origin value of the policy property specifies that the browsing context should only be allowed to navigate to URLs that have the same origin as the current page. This helps protect against certain types of attacks, such as cross-origin phishing and cross-site tab-nabbing.

// In brief, the crossOriginOpenerPolicy header helps to isolate browsing contexts between different origins, which can help to prevent potential cross-origin attacks.
  crossOriginOpenerPolicy: {
    policy: "same-origin",
  },
 // The crossOriginResourcePolicy option in Helmet is used to control how resources from your site can be loaded cross-origin. The policy property can be set to one of the following values:
    // same-origin: This is the default value. It prevents resources from being loaded from other origins.
    // same-origin-allow-opener: This allows resources to be loaded from other origins, but only if they are opened by your site.
    // unsafe-inline: This allows resources to be loaded from any origin, even if they are not opened by your site. This is very insecure and should not be used.
    // none: This disables the Cross-Origin Resource Policy header.
    crossOriginResourcePolicy: {
      // To load resources from other origins in this case, you would need to set the crossOriginResourcePolicy option to same-origin-allow-opener. This would allow resources from other origins to be loaded, but only if they are opened by your site.
      policy: 'same-origin-allow-opener',
    },
    // The originAgentCluster option in Helmet is used to control how process isolation is handled in your application. When this option is set to true, it tells the browser to isolate each request based on the origin and user agent of the request. This helps to protect your application from cross-site request forgery (CSRF) attacks.

    //CSRF attacks are a type of attack where an attacker tricks a user into making a malicious request to your application. This can be done by embedding a malicious link in an email or social media post. When the user clicks on the link, it will make a request to your application with the user's credentials. If the request is not properly protected, the attacker can then use the user's credentials to make unauthorized changes to the user's account.

    // Setting the originAgentCluster option to true helps to protect your application from CSRF attacks by isolating each request based on the origin and user agent of the request. This means that even if the user clicks on a malicious link, the request will only be able to access resources from the same origin as the link. This prevents the attacker from using the user's credentials to make unauthorized changes to the user's account.
    originAgentCluster: true,
    // If you do not set the referrerPolicy header, the Referrer header will be set to the URL of the page that the user was on before they came to your site. The Referrer header can store up to 5 previous URLs, but the actual number of URLs that are stored can vary depending on the browser and the operating system. For example, Chrome stores up to 5 previous URLs, while Firefox stores up to 3 previous URLs. example case If a user visited 2 sites where the Referrer Policy was not set, the 2 URLs will be stored in the Referrer header. When the user visits your website where the Referrer Policy is set to no-referrer, the Referrer header will not be set at all. This means that the 2 URLs that were stored in the Referrer header will be discarded.


    referrerPolicy: 'no-referrer',
    // If you set the xContentTypeOptions header to true, the browser will not be able to MIME sniff files. This means that the browser will not be able to guess the MIME type of a file based on its filename or extension. Instead, the browser will need to rely on the MIME type that is set in the Content-Type header. If a malicious user tries to send a file with a malicious MIME type to the / route, the browser will not be able to render the file. This will help to protect your site from malicious files.
    xContentTypeOptions: true,
    // The helmet.dnsPrefetchControl() middleware sets the X-DNS-Prefetch-Control header on your HTTP responses. This header controls DNS prefetching, which is a feature by which browsers proactively perform domain name resolution on both links that the user may choose to follow as well as URLs for items referenced by the document, including images, CSS, JavaScript, and so forth.

    // This functionhe 'off' option for helmet.dnsPrefetchControl() tells the browser to disable DNS prefetching. This can improve user privacy, as it prevents the browser from sending DNS queries for domains that the user may not actually visit. However, it can also slightly decrease performance, as the browser will have to resolve DNS queries when the user actually clicks on a link.
    // the browser guesses the domain/link the user might click on next based on either user's browsing history or on the current site the user is in.
    xDnsPrefetchControl: 'off',
    // The helmet.xDownloadOptions() middleware sets the X-Download-Options header on your HTTP responses. This header controls how browsers handle downloads. The 'noopen' option for helmet.xDownloadOptions() tells the browser to not open downloaded files in the browser window. Instead, the user will be prompted to save the file to their computer.This can help to protect users from malicious downloads, as it prevents them from being tricked into running malicious code.

    // example: Suppose your app allows users to download files. A malicious user could upload a malicious file to your app, and then trick a user into downloading the file. If the user's browser opens the file in the browser window, the malicious code could be executed. However, if the user's browser is configured to honor the X-Download-Options: noopen header, the file will not be opened in the browser window. Instead, the user will be prompted to save the file to their computer. This will prevent the malicious code from being executed.
    xDownloadOptions: 'noopen',
    //     The helmet.xFrameOptions() middleware sets the X-Frame-Options header on your HTTP responses. This header controls whether or not a browser can be embedded in an iframe. The 'deny' option for helmet.xFrameOptions() tells the browser to not embed your app in an iframe.

    // This can help to protect your app from clickjacking attacks, which are a type of attack where a malicious website tricks a user into clicking on a link that they think is from your app, but is actually from the malicious website.

    // For example, suppose you have a website that allows users to login to their accounts. A malicious website could embed your website in an iframe on their website. They could then make the iframe look like a login page for a different website, such as a bank or a social media platform. If a user clicks on the login button on the iframe, they will actually be logging into the malicious website.

    // The X-Frame-Options header can help to protect your app from clickjacking attacks by telling the browser to not embed your app in an iframe. This will prevent a malicious website from embedding your app in an iframe and tricking users into clicking on malicious links.


    xFrameOptions: 'deny',
//     By setting the X-Permitted-Cross-Domain-Policies header to none, you are effectively disabling cross-domain policies. This means that no content from your website will be able to interact with content from other websites. This can be a good security measure, as it can help to prevent cross-site scripting (XSS) attacks and other attacks that exploit cross-domain vulnerabilities.

// However, there are some drawbacks to setting the X-Permitted-Cross-Domain-Policies header to none. For example, it will prevent your website from being embedded in other websites. If you want to allow your website to be embedded in other websites, then you will need to use a different value for the header.

// Ultimately, the decision of whether or not to set the X-Permitted-Cross-Domain-Policies header to none is a trade-off between security and functionality. If you are concerned about security, then setting the header to none is a good option. However, if you need your website to be embedded in other websites, then you will need to use a different value for the header.
    xPermittedCrossDomainPolicies: 'none',
  }),(req:any, res:any, next:any) => {
// calling next middleware in the queue    next();
  });

// The express() function returns an app object, which is the main application object in Express. The app object can be used to configure the application, such as setting the port number, loading middleware, and defining routes.

// The express.router() function returns a router object, which is a smaller, more isolated object that can be used to define routes. Router objects are often used to group related routes together.
// configuring router
const router = express.Router({
  caseSensitive: true,
  mergeParams: true,
  strict: true,
});

// required in Express when you want to parse incoming JSON requests and put the parsed data in the req.body property. This is useful when you need to access the JSON data in your routes, controllers, or other middleware.
app.use(express.json(),(req:any, res:any, next:any) => {
  // Do something with the request.
  next();
});

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
  }),(req:any, res:any, next:any) => {
    // Do something with the request.
    next();
  }
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
