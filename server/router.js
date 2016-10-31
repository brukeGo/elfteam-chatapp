'use strict';
const path = require('path');
const express = require('express');
const router = express.Router();
const auth = require('./auth.js');

router.post('/init_reg', (req, res, next) => {
  auth.init_register(req.body.tok, (er) => {  
    if (er) {
      res.json({err: er});
    } else {
      res.json({init: 'ok'});
    }
  });
});

router.post('/reg', (req, res, next) => {
  auth.register(req.body.tok, (er) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({reg: 'ok'});
    }
  });
});

router.post('/init_login', (req, res, next) => {
  auth.init_login(req.body.tok, (er, challenge) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({challenge: challenge});
    }
  });
});

router.post('/login', (req, res, next) => {
  auth.login(req.body.tok, (er, tok) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({token: tok});
    }
  });
});

router.post('/send_frd_req', (req, res, next) => {
  auth.send_frd_req(req.decod.sub, req.body.tok, (er) => { 
    res.json({err: er});
  });
});

router.post('/fetch_frd_req', (req, res, next) => {
  auth.fetch_frd_req(req.decod.sub, (er, req) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({frd_req: req});
    }
  });
});

router.post('/fetch_frd_rej', (req, res, next) => {
  auth.fetch_frd_rej(req.decod.sub, (er, rej) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({frd_rej: rej});
    }
  });
});

router.post('/send_frd_rej', (req, res, next) => {
  auth.send_frd_rej(req.decod.sub, req.body.tok, (er) => {
    res.json({err: er});
  });
});

router.post('/msg', (req, res, next) => {
  auth.handle_msg(req.decod.sub, req.body.tok, (er) => {
    res.json({err: er});
  });
});

router.post('/unread', (req, res, next) => {
  auth.fetch_unread(req.decod.sub, (er, unread) => {
    if (er) {
      res.json({err: er});
    } else {
      res.json({unread: unread});
    }
  });
});

router.post('/logout', (req, res, next) => {
  auth.logout(req.decod, () => {
    res.json({err: null});
  });
});

module.exports = router;
