'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');
const jwt  = require('jsonwebtoken');
const levelup = require('levelup');
const router = express.Router();
const jwtkey = process.env.JWT_SECRET || fs.readFileSync(path.join(__dirname, 'certs', 'jwt-key.pem'));
var db = levelup(path.join(__dirname, 'db'));

function log(info) {
  console.log(`elfpm-server: ${info}`);
}

function find_user(username, cb) {
  var val;
  db.get(username, (err, record) => {
    if (err && err.notFound) {
      return cb(`${username} not found.`, null);
    } else if (err && !err.notFound) {
      return cb(err.message, null);
    } else {
      try {
        val = JSON.parse(record);
      } catch(ex) {
        return cb(ex.message, null);
      }
      return cb(null, val);
    }
  });
}

function update_user(username, key, val, cb) {
  find_user(username, (err, user) => {
    if (err) {
      return cb(err.message);
    }
    if (user) {
      user[key] = val;
      db.put(username, JSON.stringify(user), (err) => {
        if (err) {
          return cb(err.message);
        } else {
          console.log(user);
          return cb(null);
        }
      });
    } else {
      return cb(`${username} not found.`);
    }
  });
}

// create JWT
function gen_jwt(username) {

  // by default, expire the token after 60 mins.
  const expire_def = Math.floor(new Date().getTime()/1000) + 60*60;
  var token = jwt.sign({
    name: username,
    iat: new Date().getTime(),
    exp: expire_def
  }, jwtkey);
  return token;
}

function gen_and_store_jwt(username, cb) {
  var tok = gen_jwt(username);
  update_user(username, 'token', tok, (err) => {
    if (err) {
      return cb(err, null);
    } else {
      return cb(null, tok);
    }
  });
}

function verify_jwt(token) {
  var decoded = false;
  try {
    decoded = jwt.verify(token, jwtkey);
  } catch(err) {
    decoded = false; // still false
  }
  return decoded;
}

router.get('/', (req, res, next) => {
  res.end('elfpm server: please use the elfpm client application.');
});

router.post('/register', (req, res, next) => {
  console.log(req.body);
  var un = req.body.un;
  var pw = req.body.pw;
  if (un && pw) {

    // make sure username is unique
    find_user(un, (err, val) => {
      if (err) {
        console.log(err);
        // username is unique, save it to db
        db.put(un, JSON.stringify({"password": pw}), (err) => {
          if (err) {
            log(err.message);
          }
          log(`${un} saved to db successfully.`);
          res.json({err: null});
        });
      } else {
        log(`${un} already taken.`);
        res.json({err: `${un} already taken. Please choose another one`});
      }
    });
  } else {
    log('invalid username and/or pass');
    res.json({err: 'invalid username/password'});
  }
});

router.post('/login', (req, res, next) => {
  console.log(req.body);
  var un = req.body.un;
  var pw = req.body.pw;
  find_user(un, (error, user) => {
    if (error) {
      log(error);
      res.json({err: error});
    } else if (user && user.password && user.password === pw) {
      log(`${un} logged in successfully.`);
      gen_and_store_jwt(un, (er, tok) => {
        if (er) {
          log(er);
          res.json({err: er});
        }
        if (tok) {
          res.json({token: tok});
        }
      });
    } else {
      log(`invalid user/pass for ${un}`);
      res.json({err: 'invalid username/password'});
    }
  });
});

module.exports = router;

