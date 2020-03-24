#!/usr/bin/node

const Paseto = require('paseto.js');
const cookies = require('tough-cookie');
const got = require('got');
const { createHash } = require('crypto');
const querystring = require('querystring');
require('dotenv').config()

const { API_URL, API_KEY, API_SECRET } = process.env;

let _key = null;

async function getKey() {
  if(!_key) {
    const key = new Paseto.PrivateKey.V2();
    await key.inject(Buffer.from(API_SECRET, 'base64'));

    _key = key;
  }

  return _key;
}

async function getNonce(sess) {
  const res = await sess.post(`${API_URL}/partner/nonce`, { json: {} });
  if(!res.body.success) {
    console.error(res);
    throw new Error('bad response');
  }

  return res.headers['x-nonce'];
}

async function get(id) {
  const signer = new Paseto.V2();
  const key = await getKey();
  const sess = got.extend({ cookieJar: new cookies.CookieJar(), responseType: 'json' });
  const nonce = await getNonce(sess);

  const req = {
    id,
    apiKey: API_KEY,
    nonce: nonce,
  };
  const rawBody = Buffer.from(JSON.stringify(req));
  const hash = createHash('sha256').update(rawBody).digest('hex');
  const sig = await signer.sign(Buffer.from(hash), key);

  const res = await sess.post(`${API_URL}/partner/voucher/get`, {
    body: rawBody,
    headers: {
      "Content-Type": "application/json",
      "x-signature": sig,
    },
  });
  const voucher = res.body.voucher;

  if(!res.body.success) {
    return { success: false, upstreamResponse: res.body };
  }

  if(Date.parse(voucher.expirationDate) < Date.now()) {
    return { success: false, reason: 'expired' };
  }

  if(voucher.isUsed) {
    return { success: false, reason: 'used' };
  }

  return { success: true, voucher };
}

async function use(cartAmount, vouchers) {
  const key = await getKey();
  const signer = new Paseto.V2();
  const sess = got.extend({ cookieJar: new cookies.CookieJar(), responseType: 'json' });
  const nonce = await getNonce(sess);

  const req = {
    cartAmount: parseInt(cartAmount),
    vouchers,
    apiKey: API_KEY,
    nonce: nonce,
  };
  const rawBody = Buffer.from(JSON.stringify(req));
  const hash = createHash('sha256').update(rawBody).digest('hex');
  const sig = await signer.sign(Buffer.from(hash), key);

  try {
    const res = await sess.post(`${API_URL}/partner/voucher/use`, {
      body: rawBody,
      headers: {
        "Content-Type": "application/json",
        "x-signature": sig,
      },
    });

    if(!res.body.success) {
      return { success: false, upstreamResponse: res.body };
    }

    return { success: true };
  } catch(err) {
    const res = err.response;
    console.error({ cartAmount, vouchers, result: res.body });
    throw err;
  }
}

const server = require('http').createServer((req, res) => {
  (async () => {
    const sep = req.url.indexOf("?");
    const path = sep === -1 ? req.url : req.url.slice(0, sep);
    const qs = sep === -1 ? "" : req.url.slice(sep + 1);
    const params = querystring.parse(qs);

    let result = null;

    const toArray = val => Array.isArray(val) ? val : [val];
    console.log(path);
    console.log(params);
    switch(path) {
      case "/smarketoo/voucher/get":
        result = await get(params.id);
        break;
      case "/smarketoo/voucher/use":
        result = await use(parseInt(params.cartAmount), toArray(params["vouchers[]"]));
        break;
      default:
        res.writeHeader(404);
    }

    if(!res.headersSent) {
      res.setHeader("Content-Type", "application/json");
      res.writeHeader(200);
    }

    res.write(JSON.stringify(result));
    res.end();
  })().catch(err => {
    console.error(err);
    if(!res.headersSent) {
      res.writeHeader(500);
    }
    if(err.response) {
      console.error(err.response.body);
    }
    res.end(JSON.stringify({
      success: false,
      upstreamError: (err && err.response && err.response.body || null),
    }));
  });
});

const port = process.env.LISTEN || 80;

server.listen(port, err => {
  if(err) {
    console.error(err);
    process.exit(1);
  }
  console.error(`Server ready on port ${port}`);
});
