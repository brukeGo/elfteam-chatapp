#!/usr/bin/env node

'use strict';

const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const auth = require('./auth.js');
const router = require('./router');
var app = express();
var server;

function normalizePort(val) {
  var port = parseInt(val, 10);
  if (isNaN(port)) {
    return val;
  }
  if (port >= 0) {
    return port;
  }
  return false;
}

var port = normalizePort(process.env.PORT || 8080);

function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }
  var bind = typeof port === 'string' ? 'Pipe ' + port : 'Port ' + port;
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

app.set('port', port);
server = http.createServer(app);
server.listen(port, () => {
  console.log(`elfocrypt-server listening on port ${port}..`);
});
server.on('error', onError);
app.use(helmet());
app.use(bodyParser.json({limit: '50mb'}));
app.use(bodyParser.urlencoded({limit: '50mb', extended: false}));
app.use((req, res, next) => {
  if (req.originalUrl === '/init_reg' || req.originalUrl === '/reg' || req.originalUrl === '/init_login' || req.originalUrl === '/login') {
    auth.verify_client_tag(req.headers.authorization, (er) => {
      if (er) {
        res.status(403).json({err: er});
      } else {
        next();
      }
    });
  } else {
    auth.verify_tok(req.headers.authorization, (er, decod) => {
      if (er) {
        res.status(403).json({err: er});
      } else {
        req.decod = decod;
        next();
      }
    });
  }
});
app.use('/', router);
