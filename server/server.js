#!/usr/bin/env node

'use strict';

/**
 * module dependencies.
 */

const path = require('path');
const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const router = require('./router');
var app = express();
var server;

/**
 * normalize a port into a number, string, or false.
 * (it is an express default, keep it)
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

var port = normalizePort(process.env.PORT || 8080);

/**
 * error event listener (it is an express default, keep it)
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
 * create HTTP server.
 */

server = http.createServer(app);

/**
 * listen on provided port, on all network interfaces.
 */

server.listen(port, () => {
  console.log(`elfocrypt-server listening on port ${port}..`);
});

server.on('error', onError);

/**
 * app view engine and middlewares
 */

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use('/', router);
