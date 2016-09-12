/**
 * handle API routes
 */

'use strict';

const express = require('express');
const router = express.Router();
const auth = require('./auth.js');

function log(info) {
  console.log(`elfpm-server: ${info}`);
}

/**
 * Get homepage, in case if someone hits the
 * server web root path, inform user to use the client application
 */

router.get('/', (req, res, next) => {
  res.end('elfpm server: please use the elfpm client application.');
});

/**
 * handle POST request to register new user
 */

router.post('/register', (req, res, next) => {
  var username = req.body.un;
  var passw = req.body.pw;
  if (username && passw) {
    auth.register(username, passw, (err, tok) => {
      if (err) {
        res.json({err: err});
      }

      // successfully created a new account
      // return the token to client
      if (tok) {
        res.json({token: tok});
      }
    });
  } else {
    res.json({err: 'invalid username/password'});
  }
});

/**
 * handle POST request to /register/pubk endpoint
 * to get new user's public key and save it to db.
 * This is a protected route. it verifies token in
 * http headers authorization.
 */

router.post('/register/auth_pubk', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.un;
  var pubkey = req.body.pubkey;

  if (tok && username && pubkey) {
    auth.save_pubkey(username, tok, pubkey, (err) => {
      if (err) {
        log(err);
        res.json({err: err});
      }
      res.json({err: null});
    });
  } else {
    log('token/username/pubkey not valid');
    res.json({err: 'token and/or username and/or public key not valid'});
  }
});

/**
 * handle POST request to /login endpoint
 */

router.post('/login', (req, res, next) => {
  var usern = req.body.un;
  var passw = req.body.pw;
  var passw_sig = req.body.pw_sig;
  auth.login(usern, passw, passw_sig, (err, tok) => {
    if (err) {
      res.json({err: err});
    }
    if (tok) {
      res.json({token: tok});
    }
  });
});

/**
 * handle POST request to /auth/add_frd endpoint
 * to add new friend to user's friend list. It is
 * an authenticated route.
 */

router.post('/auth/add_frd', (req, res, next) => {

  var tok = req.headers.authorization;
  var usern = req.body.un;
  var frd_usern = req.body.frd_un;
  auth.add_frd(usern, frd_usern, tok, (err, frd_pubkey) => {
    if (err) {
      res.json({err: err});
    }
    if (frd_pubkey) {
      res.json({pubkey: frd_pubkey});
    }
  });
});

module.exports = router;

