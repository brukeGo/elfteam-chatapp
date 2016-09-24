#!/usr/bin/env node
'use strict';

const path = require('path');
const crypto = require('crypto');
const levelup = require('levelup');
const async = require('async');
const read = require('read');
const readline = require('readline');
const io = require('socket.io-client');
const jwt = require('jsonwebtoken');
const encoding = 'base64';
const alg = 'aes-256-cbc';
const hmac_alg = 'sha256';
const arg = process.argv[2];

const sock = io.connect('https://localhost.daplie.com:3761/live/auth');

/**
 * create an elliptic curve Diffie-Hellman key exchange for this
 * private chat session and generate the client dh public key 
 * to send to the other client
 */

const client_dh = crypto.createECDH('secp521r1');
const clientkey = client_dh.generateKeys(encoding);

var db = levelup(path.resolve('..', 'db'));

function er(error) {
  console.error(`\nerror: ${error}`);
}

function log(info) {
  console.log(`\n${info}`);
}

function exit(code) {
  sock.disconnect();
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

function logout(cb) {  
  db.get('tok', (err, tok) => {
    if (err) {
      er(err.message);
      return cb(err.message);
    }
    sock.emit('logout', {token: tok}).on('logout-err', (err) => {
      er(err);
      return cb(err);
    }).on('logout-success', (dat) => {
      db.batch().del('tok').del('session_dat').write(() => {
        log(dat);
        return cb();
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
    login_sock.emit('login', {un: usern, pw: passw, pw_sig: sig}).on('login-err', (err) => {  
      login_sock.disconnect();
      return cb(err);
    }).on('login-success', (dat) => {  
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

function gen_jwt(dat, cb) {
  var tok;
  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message);
    }
    dat = Object.assign(dat, {iat: new Date().getTime(), exp: Math.floor(new Date().getTime()/1000) + 60*60});
    // sign jwt asymmetric with RSA SHA256
    tok = jwt.sign(dat, privkey, {algorithm: 'RS256'});
    return cb(null, tok);
  });
}

function verify_tok(token, frd, cb) {
  get_frd_pubkey(frd, (err, frd_pubkey) => {
    if (err) {
      return cb(err);
    }
    // verify jwt asymmetric
    jwt.verify(token, frd_pubkey, (err, decod) => {
      if (err) {
        return cb(err.message);
      } else {
        return cb(null, decod);
      }
    });
  });
}

process.on('SIGINT', () => {
  logout((err) => {
    if (err) {
      er(err);
      exit(1);
    }
    exit(0);
  });
});

if (arg === 'login') {
  console.log();
  read({prompt: 'username: '}, (err, usern) => {
    if (err) {
      er(err);
      exit(1);
    }
    read({prompt: 'password: ', silent: true}, (err, passw) => {
      if (err) {
        er(err);
        exit(1);
      }
      login(usern, passw, (err) => {
        if (err) {
          er(err);
          exit(1);
        } else {
          exit(0);
        }
      });
    });
  });
} else if (arg !== 'login' && arg !== undefined && arg !== '') {
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
      sock.emit('authenticate', {token: tok}).on('authenticated', () => {  
        var rl = readline.createInterface({input: process.stdin, output: process.stdout});
        log(`a private chat request sent to ${arg}, waiting for a response..`);

        // send a private chat request to a friend
        sock.emit('req-chat', {sender: username, receiver: arg}).on('req-chat-reject', (dat) => {  
          log(`${dat.receiver} rejected the offer`);
          logout((err) => {
            if (err) {
              er(err);
              exit(1);
            }
            exit(0);
          });
        }).on('priv-chat-accepted', (dat) => {  
          var dh_sec;
          verify_tok(dat.token, dat.receiver, (err, decod) => {
            if (err) {
              er(err);
              exit(1);
            }
            if (decod && decod.dh) {
              dh_sec = client_dh.computeSecret(decod.dh, encoding, encoding);
              db.put('dh_sec', dh_sec, (err) => {
                if (err) {
                  er(err.message);
                  exit(1);
                }
                gen_jwt({dh: clientkey}, (err, tok) => {
                  if (err) {
                    er(err);
                    exit(1);
                  }
                  dat = Object.assign(dat, {token: tok});
                  sock.emit('priv-chat-sender-key', dat);
                });
              });
            } else {
              er('token not valid');
              exit(1);
            }
          });
        }).on('priv-chat-ready', (dat) => {  
          db.put('session_dat', JSON.stringify(dat), (err) => {
            if (err) {
              er(err.message);
              exit(1);
            } else {
              log(`${dat.sender} and ${dat.receiver} are ready to have a private conversation`);
              rl.setPrompt(`${dat.sender}: `);
              rl.prompt();
            }
          });
        });

        sock.on('priv-msg-res', (dat) => {
          console.log(`\n${dat.sender}: ${dat.msg}`);
          rl.prompt();
        });

        rl.on('line', (msg) => {
          var dat;
          db.get('session_dat', (err, session_dat) => {
            if (err) {
              er(err);
              exit(1);
            }
            try {
              dat = JSON.parse(session_dat);
            } catch(err) {
              er(err);
              exit(1);
            }
            sock.emit('priv-msg', {room: dat.room, sender: dat.sender, msg: msg});
            rl.prompt();
          });
        }).on('close', () => {
          logout((err) => {
            if (err) {
              er(err);
              exit(1);
            }
            exit(0);
          });
        });
      }).on('unauthorized', (msg) => {
        er(`socket unauthorized: ${JSON.stringify(msg.data)}`);
        er(msg.data.type);
        exit(1);
      });
    }); 
  });
} else {
  db.get('tok', (err, tok) => {
    if (err) {
      er(err);
      exit(1);
    }
    sock.emit('authenticate', {token: tok}).on('authenticated', () => {  
      var rl = readline.createInterface({input: process.stdin, output: process.stdout});
      log('Your friends private chat requests will be shown up here when they received..');

      // receive a private chat request from a friend  
      sock.on('req-priv-chat', (dat) => {
        rl.question(`\n${dat.sender} wants to have a private conversation. Do you accept? [y/n] `, (ans) => {
          if (ans.match(/^y(es)?$/i)) {  
            gen_jwt({dh: clientkey}, (err, tok) => {
              if (err) {
                er(err);
                exit(1);
              }
              dat = Object.assign(dat, {token: tok});
              sock.emit('req-priv-chat-accept', dat);
            });
          } else {
            sock.emit('req-priv-chat-reject', dat);
            log(`a reject response sent to ${dat.sender}`);
          }
        });
      });
      sock.on('priv-chat-sender-pubkey', (dat) => {  
        var dh_sec;
        verify_tok(dat.token, dat.sender, (err, decod) => {
          if (err) {
            er(err);
            exit(1);
          }
          if (decod && decod.dh) {
            dh_sec = client_dh.computeSecret(decod.dh, encoding, encoding);
            db.put('dh_sec', dh_sec, (err) => {
              if (err) {
                er(err);
                exit(1);
              }
              sock.emit('priv-chat-key-exchanged', {
                room: dat.room,
                sender: dat.sender,
                receiver: dat.receiver
              });
            });
          } else {
            er('token not valid');
            exit(1);
          }
        });
      }); 
      sock.on('priv-chat-ready', (dat) => {  
        db.put('session_dat', JSON.stringify(dat), (err) => {
          if (err) {  
            er(err.message);
            rl.close();
            exit(1);
          } else {
            log(`${dat.sender} and ${dat.receiver} are ready to have a private conversation`);
            rl.setPrompt(`${dat.receiver}: `);
            rl.prompt();
          }
        });
      });  
      sock.on('priv-msg', (dat) => {
        console.log(`\n${dat.sender}: ${dat.msg}`);
        rl.prompt();
      });

      rl.on('line', (msg) => {  
        var dat;
        db.get('session_dat', (err, session_dat) => {
          if (err) {
            er(err.message);
            rl.close();
            exit(1);
          }
          try {
            dat = JSON.parse(session_dat);
          } catch(err) {
            er(err);
            exit(1);
          }
          sock.emit('priv-msg-res', {room: dat.room, sender: dat.receiver, msg: msg});
          rl.prompt();
        });
      }).on('close', () => {
        logout((err) => {
          if (err) {
            er(err);
            exit(1);
          }
          exit(0);
        });
      }).on('unauthorized', (msg) => {
        er(`socket unauthorized: ${JSON.stringify(msg.data)}`);
        er(msg.data.type);
        exit(1);
      });
    });
  });
}
