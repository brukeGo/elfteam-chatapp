#!/usr/bin/env node

'use strict';

/**
 * module dependencies.
 */

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const http = require('http');
const https = require('https');
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const socketioJwt = require('socketio-jwt');
const router = require('./router');
const auth = require('./auth.js');
var app = express();
var server, socket_io, login_io, io;

/**
 * tls options
 */

const options = {
  key: fs.readFileSync(path.join(__dirname, 'certs', 'privkey.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'fullchain.pem')),
  dhparam: fs.readFileSync(path.join(__dirname, 'certs', 'dh.pem')),
  SNICallback: function(domainname, cb) {

    // normally check the domainname choose the correct certificate,
    // but for testing/dev always use this one (the default) instead
    cb(null, tls.createSecureContext(options));
  },
  NPNProtcols: ['http/1.1']
};

function log(info) {
  console.log(`elfpm-server: ${info}`);
}

/**
 * normalize a port into a number, string, or false.
 */

function normalizePort(val) {
  var port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}

var port = normalizePort(process.env.PORT || 3761);

/**
 * 'error' event listener
 */

function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }

  var bind = typeof port === 'string' ? 'Pipe ' + port : 'Port ' + port;

  // handle specific listen errors with friendly messages
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * get port from environment and store in Express.
 */

app.set('port', port);

/**
 * redirect http requests to https
 */

http.createServer((req, res) => {
  res.writeHead(301, {"Location": "https://" + req.headers.host + req.url});
  res.end();
}).listen(3571);

/**
 * create HTTPS server.
 */

server = https.createServer(options, app);
//var server = http.createServer(app);

/**
 * listen on provided port, on all network interfaces.
 */

server.listen(port, () => {
  console.log(`elfpm-server listening on port ${port}..`);
});

server.on('error', onError);

/**
 * app view engine and middlewares
 */

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
// use helmet which consists of 9 different security
// middlewares for setting http headers appropriately
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use('/', router);

/**
 * live chat server using socket.io custom namespaces
 * for login and authenticated paths
 */

socket_io = require('socket.io')(server);
login_io = socket_io.of('/live/login');
io = socket_io.of('/live/auth');

login_io.on('connection', (sock) => {
  sock.on('login', (dat) => {
    if (dat.un && dat.pw && dat.pw_sig) {
      auth.login(dat.un, dat.pw, dat.pw_sig, (err, tok) => {
        if (err) {
          sock.emit('login-err', err);
          sock.disconnect();
        }
        if (tok) {
          log(`${dat.un} logged in successfully`);
          sock.emit('login-success', {token: tok});
          sock.disconnect();
        }
      }); 
    } else {    
      sock.emit('login-err', 'username/pass/sig not valid');
      sock.disconnect();
    }
  });
});

// authenticated sockets
io.on('connection', socketioJwt.authorize({
  secret: auth.jwtkey,
  callback: false,
  timeout: 15000
})).on('authenticated', (sock) => {
  // this socket is authenticated, we can handle more events
  log(`${sock.decoded_token.nam} authenticated successfully`);
  sock.join(sock.decoded_token.nam);

  sock.on('req-chat', (dat) => {
    sock.join(`${dat.sender}-${dat.receiver}`);
    sock.to(dat.receiver).emit('req-priv-chat', dat);
  });

  sock.on('req-priv-chat-reject', (dat) => {
    io.to(dat.sender).emit('req-chat-reject', dat);
  });

  sock.on('req-priv-chat-accept', (dat) => {
    sock.join(`${dat.sender}-${dat.receiver}`);
    sock.to(dat.sender).emit('priv-chat-accepted', {
      room: `${dat.sender}-${dat.receiver}`,
      sender: dat.sender,
      receiver: dat.receiver
    });
  });

  // sender send his/her fresh diffie-hellman encrypted public key
  sock.on('priv-chat-key-sender', (dat) => {
    sock.broadcast.to(dat.room).emit('priv-chat-sender-pubkey', dat);
  });

  // receiver respond back with his/her newly generated dh public key
  sock.on('priv-chat-receiver-pubkey', (dat) => {
    sock.broadcast.to(dat.room).emit('priv-chat-key-receiver', dat);
  });

  sock.on('priv-chat-key-exchanged', (dat) => {
    sock.to(dat.room).emit('priv-chat-ready', dat);
  });

  sock.on('priv-msg', (dat) => {
    sock.broadcast.to(dat.room).emit('priv-msg', dat);
  });
  sock.on('priv-msg-res', (dat) => {
    sock.broadcast.to(dat.room).emit('priv-msg-res', dat);
  });

  sock.on('logout', (dat) => {
    auth.logout(dat.token, sock.decoded_token.nam, (err) => {
      if (err) {
        log(err);
        sock.emit('logout-err', err);
        sock.disconnect();
      } else {
        sock.emit('logout-success', `logged out successfully`);
        sock.disconnect();
      }
    });
  });
});

