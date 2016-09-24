#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const levelup = require('levelup');
const async = require('async');
const read = require('read');
const readline = require('readline');
const io = require('socket.io-client');
const encoding = 'base64';
const alg = 'aes-256-cbc';
const hmac_alg = 'sha256';
const arg = process.argv[2];
var db = levelup(path.resolve('..', 'db'));

const sock = io.connect('https://localhost.daplie.com:3761/live/auth');

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
    sock.emit('logout', {token: tok}).on('logout-err', (err) => {
      er(err);
      return cb(err);
    }).on('logout-success', (dat) => {
      db.batch().del('tok').del('room').write(() => {
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
    login_sock.emit('login', {un: usern, pw: passw, pw_sig: sig})
      .on('login-err', (err) => {
        login_sock.disconnect();
        return cb(err);
      })
      .on('login-success', (dat) => {
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
      sock.emit('authenticate', {token: tok})
        .on('authenticated', () => {
          log(`a private chat request sent to ${arg}, waiting for a response..`); 
          var rl = readline.createInterface({input: process.stdin, output: process.stdout});

          // send a private chat request to a friend
          sock.emit('req-chat', {sender: username, receiver: arg})
            .on('req-chat-reject', (dat) => {
              log(`${dat.receiver} rejected the offer`);
              logout((err) => {
                if (err) {
                  er(err);
                  exit(1);
                }
                exit(0);
              });
            }).on('priv-chat-accepted', (dat) => {
              gen_and_encrypt_dh(dat, (err, dhpubkey) => {
                if (err) {
                  er(err);
                  exit(1);
                }
                dat = Object.assign(dat, {dh_sender: dhpubkey});
                console.log(dat);
                sock.emit('priv-chat-key-sender', dat);
              });
            }).on('priv-chat-key-receiver', (dat) => {
              // we received friend's encrypted diffie-hellman public key
              // decrypt it and compute the dh secret and save it to db
              // for this private chat session encryption
              decrypt_and_compute_dh(dat, (err) => {
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
            }).on('priv-chat-ready', (dat) => {
              db.put('livechat_dat', dat, (err) => {
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
            db.get('livechat_dat', (err, dat) => {
              if (err) {
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
  log('Your friends private chat requests will be shown up here when they received..');
  db.get('tok', (err, tok) => {
    if (err) {
      er(err);
      exit(1);
    }
    sock.emit('authenticate', {token: tok})
      .on('authenticated', () => {
        var rl = readline.createInterface({input: process.stdin, output: process.stdout});

        // receive a private chat request from a friend
        sock.on('req-priv-chat', (dat) => {
          rl.question(`\n${dat.sender} wants to have a private conversation. Do you accept? [y/n] `, (ans) => {
            if (ans.match(/^y(es)?$/i)) {
              sock.emit('req-priv-chat-accept', dat);
            } else {
              sock.emit('req-priv-chat-reject', dat);
              log(`a reject response sent to ${dat.sender}`);
            }
          });
        });
        sock.on('priv-chat-sender-pubkey', (dat) => {
          gen_and_encrypt_dh(dat, (err, dhpubkey) => {
            if (err) {
              er(err);
              exit(1);
            }
            dat = Object.assign(dat, {dh_receiver: dhpubkey});
            sock.emit('priv-chat-receiver-pubkey', dat);
          });
        });
        sock.on('priv-chat-ready', (dat) => {
          db.put('livechat_dat', dat, (err) => {
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
          db.get('livechat_dat', (err, dat) => {
            if (err) {
              er(err.message);
              rl.close();
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
