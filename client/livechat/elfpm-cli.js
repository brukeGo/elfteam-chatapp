#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const levelup = require('levelup');
const async = require('async');
const readline = require('readline');
const io = require('socket.io-client');
const encoding = 'base64';
const alg = 'aes-256-cbc';
const hmac_alg = 'sha256';
const cmd = process.argv[2];
var db = levelup(path.resolve('..', 'db'));

const sock = io.connect('https://localhost.daplie.com:3761/live/auth');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function er(error) {
  console.error(`\nerror: ${error}`);
}

function log(info) {
  console.log(`\n${info}`);
}

function exit(code) {
  process.exit(code);
}

function gen_sign(data, cb) {
  var sign;
  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message, null);
    }
    sign = crypto.createSign('RSA-SHA256');
    sign.write(data);
    sign.end();
    return cb(null, sign.sign(privkey, encoding));
  });
}

function get_frds(cb) {
  var frds;
  db.get('frd', (err, val) => {
    if (err) {
      return cb();
    }
    try {
      frds = JSON.parse(val);
    } catch(er) {
      return cb(er.message, null);
    }
    if (frds.ls.length > 0) {
      return cb(null, frds.ls);
    } else {
      return cb();
    }
  });
}

function get_frd_pubkey(frd_username, cb) {
  var frd_pubkey;
  get_frds((err, frds) => {
    if (err) {
      return cb(err, null);
    }
    frds.forEach((frd) => {
      if (frd.pubkey && frd.name === frd_username) {
        frd_pubkey = Buffer.from(frd.pubkey, encoding).toString();
      }
    });
    return cb(null, frd_pubkey);
  });
}

function enc(msg, receiver, cb) {
  var msg_key, hmac_key, iv,
    hmac, tag, keys_encrypted, cipher, cipher_text;

  get_frd_pubkey(receiver, (err, rec_pubkey) => {
    if (err) {
      return cb(err, null);
    }
    if (rec_pubkey) {
      // we have receiver's pubkey, try to
      // encrypt the message
      try {
        msg_key = crypto.randomBytes(32);
        hmac_key = crypto.randomBytes(32);
        iv = crypto.randomBytes(16); // initialization vector 128 bits
        hmac = crypto.createHmac(hmac_alg, hmac_key);

        // encrypt the message with random iv
        cipher = crypto.createCipheriv(alg, msg_key, iv);
        cipher_text = cipher.update(msg, 'utf8', encoding);
        cipher_text += cipher.final(encoding);

        // make sure both the cipher text and
        // the iv are protected by hmac
        hmac.update(cipher_text);
        hmac.update(iv.toString(encoding));
        tag = hmac.digest(encoding);

        // encrypt concatenated msg and hmac keys with receiver's public key
        keys_encrypted = crypto.publicEncrypt(rec_pubkey, Buffer.from(`${msg_key.toString(encoding)}&${hmac_key.toString(encoding)}`));

        // concatenate keys, cipher text, iv and hmac digest
        return cb(null, `${keys_encrypted.toString(encoding)}#${cipher_text}#${iv.toString(encoding)}#${tag}`);
      } catch(err) {
        return cb(err.message, null);
      } 
    }
  });
}

function dec(cipher_text, cb) {
  var chunk, keys_encrypted, keys_dec, 
    ct, iv, tag, msg_key, hmac_key, hmac,
    computed_tag, decipher, decrypted;

  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message, null);
    }
    try {
      chunk = cipher_text.split('#');
      keys_encrypted = Buffer.from(chunk[0], encoding);
      ct = chunk[1];
      iv = Buffer.from(chunk[2], encoding);
      tag = chunk[3];
      keys_dec = crypto.privateDecrypt(privkey, keys_encrypted).toString('utf8').split('&');
      msg_key = Buffer.from(keys_dec[0], encoding);
      hmac_key = Buffer.from(keys_dec[1], encoding);

      hmac = crypto.createHmac(hmac_alg, hmac_key);
      hmac.update(ct);
      hmac.update(iv.toString(encoding));
      computed_tag = hmac.digest(encoding);
      if (computed_tag !== tag) {
        return cb('integrity tag not valid', null);
      }
      decipher = crypto.createDecipheriv(alg, msg_key, iv);
      decrypted = decipher.update(ct, encoding, 'utf8');
      decrypted += decipher.final('utf8');
      return cb(null, decrypted);
    } catch(err) {
      return cb(err.message, null);
    }
  });
}
/*
function dec_and_save_unread(unread_msgs, cb) {
  var msgs;
  db.get('unread', (err, val) => {
    if (err) {
      return cb();
    }
    try {
      msgs = JSON.parse(val);
    } catch(err) {
      return cb(err.message);
    }
    async.each(unread_msgs, (unread, callback) => {
      if (!unread.sender || !unread.msg) {
        return callback('invalid unread message');
      } else {
        dec(unread.msg, (err, decrypted) => {
          if (err) {
            return callback(err);
          } else {
            msgs.ls.push({sender: unread.sender, msg: decrypted, time: unread.time});
            db.put('unread', JSON.stringify(msgs), (err) => {
              if (err) {
                return callback(err.message);
              } else {
                return callback();
              }
            });
          }
        });
      }
    }, (err) => {
      if (err) {
        return cb(err);
      } else {
        return cb();
      }
    });
  });
}
*/

function logout(cb) {  
  db.get('tok', (err, tok) => {
    if (err) {
      er(err.message);
      return cb(err.message);
    }
    sock.emit('logout', {token: tok});
    sock.on('logout-err', (err) => {
      er(err);
      return cb(err);
    });
    sock.on('logout-success', (dat) => {
      db.del('tok', (err) => {
        if (err) {
          return cb(err.message);
        } else {
          log(dat);
          log('token deleted successfully');
          return cb();
        }
      });
    });
  });  
}

function login(usern, passw, cb) {
  const login_sock = io.connect('https://localhost.daplie.com:3761/live/login');
  gen_sign(passw, (err, sig) => {  
    if (err) {
      login_sock.disconnect();
      return cb(err);
    }
    login_sock.emit('login', {un: usern, pw: passw, pw_sig: sig});
    login_sock.on('login-err', (err) => {
      login_sock.disconnect();
      return cb(err);
    });
    login_sock.on('login-success', (dat) => {
      if (dat.token) {
        db.put('tok', dat.token, (err) => {
          if (err) {
            login_sock.disconnect();
            return cb(err.message);
          } else {
            log('logged in successfully');
            login_sock.disconnect();
            return cb();
          }
        });
      } else {
        er('server-err: no authorization token');
        login_sock.disconnect();
        return cb('server-err: no authorization token');
      }
    });
  });
}

rl.on('SIGINT', () => {
  logout((err) => {
    if (err) {
      er(err);
    }
    exit(0);
  });
});

process.on('SIGINT', () => {
  logout((err) => {
    if (err) {
      er(err);
    }
    exit(0);
  });
});

if (cmd === 'login') {
  rl.question('\nusername: ', (usern) => {
    rl.question('password: ', (passw) => {
      login(usern, passw, (err) => {
        if (err) {
          er(err);
          rl.close();
          exit(1);
        } else {
          rl.close();
          exit(0);
        }
      });
    });
  });
} else if (cmd === 'req' && process.argv[3] !== null) {
  db.get('name', (err, username) => {
    if (err) {
      er(err.message);
      sock.disconnect();
      exit(1);
    }
    db.get('tok', (err, tok) => {
      if (err) {
        er(err);
        sock.disconnect();
        exit(1);
      }
      sock.emit('authenticate', {token: tok})
        .on('authenticated', () => {
          log(`a private chat request sent to ${process.argv[3]}, waiting for a response..`);
          sock.emit('req-chat', {sender: username, receiver: process.argv[3]});
          sock.on('req-chat-reject', (dat) => {
            log(`${dat.receiver} rejected the offer`);
          });
          sock.on('priv-chat-ready', (dat) => {
            log(dat);
          }); 
        }).on('unauthorized', (msg) => {
          er(`socket unauthorized: ${JSON.stringify(msg.data)}`);
          er(msg.data.type);
          sock.disconnect();
          exit(1);
        });
    });
  });
} else if (cmd === 'w') {
  log('alright, private chat requests will be shown up here when they received..');
  db.get('tok', (err, tok) => {
    if (err) {
      er(err);
      exit(1);
    }
    sock.emit('authenticate', {token: tok})
      .on('authenticated', () => {
        sock.on('req-priv-chat', (dat) => {
          rl.question(`\n${dat.sender} wants to have a private conversation. Do you accept? [y/n] `, (ans) => {
            if (ans.match(/^y(es)?$/i)) {
              sock.emit('req-priv-chat-accept', dat);
            } else {
              sock.emit('req-priv-chat-reject', dat);
              sock.disconnect();
            }
            rl.close();
          });
        });
        sock.on('priv-chat-ready', (dat) => {
          log(dat);
        }); 
      }).on('unauthorized', (msg) => {
        er(`socket unauthorized: ${JSON.stringify(msg.data)}`);
        er(msg.data.type);
        sock.disconnect();
        exit(1);
      });
  });
} else {
  er('command not found');
  exit(0);
}
