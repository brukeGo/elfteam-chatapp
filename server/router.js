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
 * Get /search endpoint
 */

router.get('/search', (req, res, next) => {
  res.render('search', {err: null});
});

/**
 * Get homepage, in case someone hits the homepage
 * redirect to /search endpoint
 */

router.get('/', (req, res, next) => {
  res.redirect('/search');
});

/**
 * search username to send public key and its signature
 */

router.post('/search', (req, res, next) => {
  var username = req.body.username;
  if (username) {
    auth.search(username, (err, user) => {
      if (err) {
        res.render('search', {err: `'${username}' not found.`});
      }
      if (user) {
        res.json({
          username: username,
          public_key: user.pubkey,
          public_key_signature: user.sig
        });
      }
    });
  } else {
    res.render('search', {err: `'${username}' not found.`});
  }
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
 * This is a protected route. it verifies token received
 * from the client in the http headers authorization.
 */

router.post('/register/auth_pubk', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.un;
  var pubkey = req.body.pubkey;
  var sig = req.body.sig;
  if (tok && username && pubkey && sig) {
    auth.save_pubkey(tok, username, pubkey, sig, (err) => {
      if (err) {
        log(err);
        res.json({err: err});
      } else {
        res.json({err: null});
      }
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
 * handle post request when client sends a message
 */

router.post('/auth_msg', (req, res, next) => {
  var tok = req.headers.authorization;
  var sender = req.body.sender;
  var receiver = req.body.rec;
  var msg = req.body.msg;

  if (tok && sender && receiver && msg) {
    // validate received data and save the msg to 
    // receiver's db record for pushing it to client
    // the next time gets online
    auth.handle_msg(tok, sender, receiver, msg, (err) => {
      if (err) {
        res.json({err: err});
      } else {
        res.json({err: null});
      }
    });
  } else {
    log('token/username not valid');
    res.json({err: 'token/username not valid'});
  }
});

/**
 * handle post request to get unread messages
 */

router.post('/auth_unread', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.un;
  if (tok && username) {
    // check for client's unread messages
    auth.get_unread(tok, username, (err, unread) => {
      if (err) {
        res.json({err: err});
      } 
      if (unread) {
        res.json({unread: unread});
      } else {
        res.json({err: null});
      }
    });
  } else {
    log('token/username not valid');
    res.json({err: 'token/username not valid'});
  }
});

/**
 * handle post request to clear client's list of unread messages
 */

router.post('/auth_clear_unread', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.un;
  if (tok && username) {
    auth.clear_unread(tok, username, (err) => {
      if (err) {
        log(err);
        res.json({err: err});
      } else {
        res.json({err: null});
      }
    });
  }
});

/**
 * log out the client and delete the saved token
 */

router.post('/auth_logout', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.un;
  if (tok && username) {
    auth.logout(tok, username, (err) => {
      if (err) {
        log(err);
        res.json({err: err});
      } else {
        res.json({err: null});
      }
    });
  }
});


module.exports = router;

