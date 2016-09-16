/**
 * handle authentication and database operations
 */

'use strict';

const path = require('path');
const jwt = require('jsonwebtoken');
const levelup = require('levelup');
const crypto = require('crypto');
const jwtkey = process.env.JWT_SECRET = crypto.randomBytes(256).toString('base64');
var db = levelup(path.join(__dirname, 'db'));

function log(info) {
  console.log(`elfpm-server: ${info}`);
}

/**
 * find user in db
 */

function find_user(username, cb) {
  var user;
  db.get(username, (err, record) => {
    if (err) {
      return cb(err.message, null);
    } else {
      try {
        user = JSON.parse(record);
      } catch(ex) {
        return cb(ex.message, null);
      }
      return cb(null, user);
    }
  });
}

/**
 * update user with given key/value item (get/put)
 */

function update_user(username, item, cb) {
  find_user(username, (err, user) => {
    if (err) {
      return cb(err);
    }
    if (user) {
      user = Object.assign(user, item);
      db.put(username, JSON.stringify(user), (err) => {
        if (err) {
          return cb(err.message);
        } else {
          return cb();
        }
      });
    } else {
      return cb(`${username} not found.`);
    }
  });
}

/*
 * create json web token for a given username,
 * sign it with server's jwtkey and return
 * the generated token.
 */

function gen_jwt(username) {

  // by default, expire the token after 24 hours (time is in secs)
  const expire_def = Math.floor(new Date().getTime()/1000) + 60*1440;
  return jwt.sign({
    nam: username,
    iat: new Date().getTime(),
    exp: expire_def
  }, jwtkey);
}

/**
 * verify a given json web token and return
 * the payload if no error found; otherwise
 * return false
 */

function verify_jwt(token) {
  var decoded = false;
  try {
    decoded = jwt.verify(token, jwtkey, {algorithms: ['HS256']});
  } catch(err) {
    decoded = false; // still false
  }
  return decoded;
}

/**
 * validate json web token for a given username
 */

function validate_token(username, token, cb) {
  var decoded;

  decoded = verify_jwt(token);
  if (!decoded || !decoded.nam) {    
    return cb('token not valid', false);
  } else {
    find_user(username, (err, user) => {
      if (err) {
        log(err);
        return cb(err, false);
      }

      // check if user's stored token matches the sent one from client
      // and also username matches token's payload name
      return cb(null, username === decoded.nam && user.token === token);
    });
  }
}

/**
 * register new user, generate a fresh json web token
 * for the current session, save it to db and return
 * the token to send to the client for subsequent
 * authenticated requests
 */

function register(username, passw, cb) {
  var tok;

  // make sure username is unique
  find_user(username, (err) => {
    if (err) {

      // username is unique, generate jwt for register
      // authentication and save it to db

      tok = gen_jwt(username);
      db.put(username, JSON.stringify({
        "password": passw,
        "token": tok
      }), (err) => {
        if (err) {
          log(err.message);
          return cb(err.message, null);
        }
        log(`${username} saved successfully`);
        return cb(null, tok);
      });
    } else {
      return cb(`'${username}' already taken. Please choose another one`, null);
    }
  });
}

/**
 * validate register jwt and store user's public key in db
 */

function save_pubkey(username, token, pubkey, sig, cb) {

  // validate the token received from client
  validate_token(username, token, (err, valid) => {
    if (err) {
      return cb(err);
    }
    // if jwt is valid, delete register token (for login we generate new token),
    // then save user's public key and its signature to db
    if (valid) {
      update_user(username, {'token': null, 'pubkey': pubkey, 'sig': sig}, (err) => {    
        if (err) {
          log(err);
          return cb(err);
        }
        return cb();
      });
    } else {
      return cb('username/token not valid');
    }
  });
}

/**
 * authenticate a returning user (login api route)
 */

function login(username, passw, passw_sig, cb) {

  const verify = crypto.createVerify('RSA-SHA256');
  var tok, valid;

  find_user(username, (error, user) => {
    if (error) {
      log(error);
      return cb(error, null);
    }
    if (user.password === passw && user.pubkey) {
      try {
        verify.write(passw);
        verify.end();

        // verify password and its signature, if successful
        // generate jwt, save it to db and send it to client

        valid = verify.verify(new Buffer(user.pubkey, 'base64').toString(), passw_sig, 'base64');
      } catch(err) {
        return cb(err.toString());
      }

      if (valid) {
        log(`${username} logged in successfully`);
        tok = gen_jwt(username);
        update_user(username, {'token': tok}, (err) => {
          if (err) {
            log(err);
            return cb(err, null);
          }
          return cb(null, tok);
        });
      } else {
        return cb('err: password/signature not valid', null);
      }
    } else {  
      return cb('err: password/signature not valid', null);
    }
  });
}

/**
 * search for a given username and return public key
 * and its signature if found, otherwise return not found err
 */

function search(username, cb) {
  find_user(username, (err, user) => {
    if (err) {
      return cb(err);
    }
    if (user.pubkey && user.sig) {
      return cb(null, {
        pubkey: user.pubkey,
        sig: user.sig
      });
    } else {
      return cb(`'${username} not found.'`);
    }
  });
}

module.exports = {
  register: register,
  save_pubkey: save_pubkey,
  login: login,
  search: search
};
