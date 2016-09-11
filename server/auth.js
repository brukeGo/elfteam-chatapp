/**
 * handle authentication and database operations
 */

'use strict';

const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const levelup = require('levelup');
const crypto = require('crypto');
const jwtkey = process.env.JWT_SECRET || fs.readFileSync(path.join(__dirname, 'certs', 'jwt-key.pem'));
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
 * update user with given key/value item
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
          console.log('\nupdated-user:\n', user);
          return cb();
        }
      });
    } else {
      return cb(`${username} not found.`);
    }
  });
}

/*
 * create json web token for a given usernam
 * and type which is register or login then
 * sign it with server's jwtkey and return
 * the generated token.
 */

function gen_jwt(username, type) {

  // by default, expire the token after 24 hours (time is in secs)
  const expire_def = Math.floor(new Date().getTime()/1000) + 60*1440;
  return jwt.sign({
    nam: username,
    typ: type,
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
    decoded = jwt.verify(token, jwtkey);
  } catch(err) {
    decoded = false; // still false
  }
  return decoded;
}

/**
 * validate json web token for a given username
 * and token type ('reg' or 'login')
 */

function validate_token(username, token, type, cb) {
  var decoded;

  // verify register jwt
  decoded = verify_jwt(token);
  if (!decoded || !decoded.nam || !decoded.typ) {    
    log('reg-token not valid');
    return cb('token not valid', false);
  } else {
    find_user(username, (err, user) => {
      if (err) {
        log(err);
        return cb(err, false);
      }

      // check if user's stored token matches the sent one from client
      // and also username matches token's payload name
      return cb(null, username === decoded.nam && 
        user.token === token && decoded.typ === type);
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
      log(err);

      // username is unique, generate jwt for register
      // authentication and save it to db

      tok = gen_jwt(username, 'reg');
      db.put(username, JSON.stringify({
        "password": passw,
        "token": tok
      }), (err) => {
        if (err) {
          log(err.message);
          return cb(err.message, null);
        }
        log(`${username} saved to db successfully.`);
        return cb(null, tok);
      });
    } else {
      log(`${username} already taken.`);
      return cb(`'${username}' already taken. Please choose another one`, null);
    }
  });
}

/**
 * verify register jwt and store user's public key in db
 */

function save_pubkey(username, token, pubkey, cb) {

  validate_token(username, token, 'reg', (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      update_user(username, {"token": null, "pubkey": pubkey}, (err) => {    
        if (err) {
          log(err);
          return cb(err);
        }

        log(`\nreg_token deleted successfully for ${username} and user pubkey saved to db successfully`);
        return cb();
      });
    } else {
      log('username/token not valid');
      return cb('username/token not valid');
    }
  });
}

/**
 * authenticate a returning user
 */

function login(username, passw, passw_sig, cb) {

  const verify = crypto.createVerify('RSA-SHA256');
  var tok;

  find_user(username, (error, user) => {
    if (error) {
      log(error);
      return cb(error, null);
    } else {
      verify.write(passw);
      verify.end();

      // verify password and its signature, if successful
      // generate jwt, save it to db and send it to client

      if (verify.verify(new Buffer(user.pubkey, 'base64').toString(), passw_sig, 'base64') && user.password === passw) {
        log(`${username} logged in successfully`);
        tok = gen_jwt(username, 'login');
        update_user(username, {'token': tok}, (err) => {
          if (err) {
            log(err);
            return cb(err, null);
          }
          return cb(null, tok);
        });
      } else {
        log('err: passw/sig not valid');
        return cb('err: password/signature not valid', null);
      }
    }
  });
}

module.exports = {
  register: register,
  save_pubkey: save_pubkey,
  login: login
};
