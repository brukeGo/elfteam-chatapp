'use strict';

const request = require('request');
const express = require('express');
const router = express.Router();
const auth = require('./auth.js');

router.post('/reg', (req, res, next) => {
  auth.register(req.body.un, req.body.pw, (er) => {
    res.json({err: er});
  });
});

router.post('/login', (req, res, next) => {
  auth.login(req.body.un, req.body.pw, (er, tok) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({token: tok});
    }
  });
});

router.post('/send_frd_req', (req, res, next) => {
  auth.send_frd_req(req.decod.nam, req.body.rec, req.body.tok, (er) => {
    res.json({err: er});
  });
});

router.post('/fetch_frd_req', (req, res, next) => {
  auth.fetch_frd_req(req.decod.nam, (er, req) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({frd_req: req});
    }
  });
});

router.post('/fetch_frd_rej', (req, res, next) => {
  auth.fetch_frd_rej(req.decod.nam, (er, rej) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({frd_rej: rej});
    }
  });
});

router.post('/send_frd_rej', (req, res, next) => {
  auth.send_frd_rej(req.decod.nam, req.body.frd, (er) => {
    res.json({err: er});
  });
});

router.post('/msg', (req, res, next) => {
  auth.handle_msg(req.decod.nam, req.body.rec, req.body.tok, req.body.time, (er) => {
    res.json({err: er});
  });
});

router.post('/unread', (req, res, next) => {
  auth.fetch_unread(req.decod.nam, (er, unread) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({unread: unread});
    }
  });
});

router.post('/logout', (req, res, next) => {
  auth.logout(req.decod.nam, (er) => {
    res.json({err: er});
  });
});

module.exports = router;
