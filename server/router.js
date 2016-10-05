/**
 * handle API routes
 */

'use strict';

const express = require('express');
const router = express.Router();
const auth = require('./auth.js');

function log(info) {
  console.log(`elfocrypt-server: ${info}`);
}

/**
 * Get homepage, in case someone hits the homepage
 * redirect to /reg endpoint
 */

router.get('/', (req, res, next) => {
  res.redirect('/reg');
});

/**
 * Get /reg endpoint
 */

router.get('/reg', (req, res, next) => {
  res.render('reg', {err: null, info: null});
});

/**
 * handle POST request to register a new user
 */

router.post('/reg', (req, res, next) => {
  var username = req.body.un;
  var passw = req.body.pw;
  if (username === '' || passw === '') {
    res.render('reg', {err: 'invalid username/password', info: null});
  } else if (username && passw) {
    auth.register(username, passw, (err) => {
      if (err) {
        res.render('reg', {err: err, info: null});
      } else {
        res.render('reg', {err: null, info: `'${username}' created successfully`});
      }
    });
  } else {
    res.render('reg', {err: 'invalid username/password', info: null});
  }
});

/**
 * handle POST request to /login endpoint
 */

router.post('/login', (req, res, next) => {
  var usern = req.body.un;
  var passw = req.body.pw;
  auth.login(usern, passw, (err, tok) => {
    if (err) {
      res.json({err: err});
    }
    if (tok) {
      res.json({token: tok});
    }
  });
});

/**
 * handle post request when user sends a friend request
 */

router.post('/auth/send_frd_req', (req, res, next) => {
  var tok = req.headers.authorization;
  var sender = req.body.sen;
  var receiver = req.body.rec;
  var frd_tok = req.body.tok;
  if (tok && sender && receiver && frd_tok) {
    auth.send_frd_req(tok, sender, receiver, frd_tok, (err) => {
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
 * handle post request when user fetches friend requests
 */

router.post('/auth/get_frd_req', (req, res, next) => {
  var tok = req.headers.authorization;
  var un = req.body.sen;
  if (tok && un) {
    auth.get_frd_req(tok, un, (err, req) => {
      if (err) {
        res.json({err: err});
      } else {
        res.json({frd_req: req});
      }
    });
  } else {
    log('token/username not valid');
    res.json({err: 'token/username not valid'});
  }
});

router.post('/auth/get_frd_rej', (req, res, next) => {
  var tok = req.headers.authorization;
  var un = req.body.sen;
  if (tok && un) {
    auth.get_frd_rej(tok, un, (err, rej) => {
      if (err) {
        res.json({err: err});
      } else {
        res.json({frd_rej: rej});
      }
    });
  } else {
    log('token/username not valid');
    res.json({err: 'token/username not valid'});
  }
});

router.post('/auth/clear_frd_req', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.sen;
  if (tok && username) {
    auth.clear_frd_req(tok, username, (err) => {
      if (err) {
        log(err);
        res.json({err: err});
      } else {
        res.json({err: null});
      }
    });
  }
});

router.post('/auth/clear_frd_rej', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.sen;
  if (tok && username) {
    auth.clear_frd_rej(tok, username, (err) => {
      if (err) {
        log(err);
        res.json({err: err});
      } else {
        res.json({err: null});
      }
    });
  }
});

router.post('/auth/rej_frd_req', (req, res, next) => {
  var tok = req.headers.authorization;
  var un = req.body.sen;
  var frd = req.body.frd;
  if (tok && un && frd) {
    auth.rej_frd_req(tok, un, frd, (err) => {
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
 * handle post request when client sends a message
 */

router.post('/auth/msg', (req, res, next) => {
  var tok = req.headers.authorization;
  var sender = req.body.sen;
  var receiver = req.body.rec;
  var msg_tok = req.body.tok;

  if (tok && sender && receiver && msg_tok) {
    // validate received data and save the msg token to 
    // receiver's db record for pushing it to client
    auth.handle_msg(tok, sender, receiver, msg_tok, (err) => {
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

router.post('/auth/unread', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.sen;
  if (tok && username) {
    // get client's unread messages
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

router.post('/auth/clear_unread', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.sen;
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

router.post('/auth/logout', (req, res, next) => {
  var tok = req.headers.authorization;
  var username = req.body.sen;
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
