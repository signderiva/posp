/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                         *
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *
 *                                                                         *
 *  2018 - Michael VERGOZ                                                  *
 *  All Rights Reserved.                                                   *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

const crypto = require('crypto');
const jen = require("node-jen")();

const allowedHashes = {
  sha256: 32,
  sha512: 64
}

const system = {
  originSecret: jen.password(128, 128),
  xHash: "sha256", // exchange hash
  posHash: "sha256" // proof of space hash
}


function _hash(algo, d) {
  const h = crypto.createHash(algo)
  h.update(d)
  return (h.digest("hex"))
}

function paramter(system) {

}

/**
 * Generate POSP from plain password (both side)
 * @param {password} password - Plain password
 * @param {cb} cb - Callback(posPassword)
 */
function generate(password, cb, opts) {
  opts = opts || {}
  opts.iterate = opts.iterate || 10
  opts.size = opts.size || 5 * 1000 * 1000
  if (!opts.hasOwnProperty('hash') || allowedHashes[opts.hash] <= 0) opts.hash = system.posHash
  const conf = {
    iterate: opts.iterate,
    size: opts.size,
    hash: opts.hash,
    salt: _hash(opts.hash, jen.password(128, 128))
  }
  const ret = cycle(conf, password)
  cb(null, ret)
}

/**
 * Compute a challenge (client-side)
 * @param {password} password - Password provided by generate() computed from client-side
 * @param {seed} seed - Challenge received from server
 * @param {cb} cb - Callback(challengeResponse)
 */
function computeChallenge(password, seed, cb) {
  var self = this;
  var pseed = seed.split(":");
  pseed.shift();
  pseed = pseed.join(':');

  this.generate(password, (digest) => {
    var cpassword = digest.split(':')[1];
    var hmac = crypto.createHmac(self.hash, cpassword);
    hmac.update(pseed);
    cb(this.prefix.challengeResponse + ":" + hmac.digest(self.encoding) + ":" + pseed)
  })
}

function cycle(conf, password) {
  const ret = { conf, size: 0, blocks: 0 }
  const startedAt = Date.now()
  const series = [];

  var last = conf.salt;
  const showMeYouHaveTheRest = (block, pos) => {
    var last = block;
    for (var a = pos; a < series.length; a++) {
      const toHash = last + series[pos] + conf.salt + password
      const hashed = _hash(conf.hash, toHash)
      last = hashed;
    }
    return (last);
  }

  // pass 1 - create initial blockchain
  do {
    const toHash = last + conf.salt + password;
    const hashed = _hash(conf.hash, toHash);
    series.push(hashed); ret.blocks++;

    last = hashed;
    ret.size += hashed.length;

  } while (ret.size < conf.size)

  // pass 2 - proove the space of series
  for (var a = conf.iterate - 1; a >= 0; a--) {
    const pos = series[a];
    const rest = showMeYouHaveTheRest(last, a);
    const toHash = last + pos + conf.salt + password + rest
    const hashed = _hash(conf.hash, toHash)

    series.push(hashed); ret.blocks++; // outch

    ret.size += hashed.length;
    last = hashed;
  }

  ret.time = Date.now() - startedAt
  ret.string = pack(conf, last)
  ret.last = last;
  return (ret)
}

function pack(conf, last) {
  return (`$POSPv1:${conf.hash}:${conf.size / 1000}:${conf.iterate}:${conf.salt}:${last}`)
}

function unpack(stored) {
  const t = stored.split(":")
  return ({
    hash: t[1],
    size: parseInt(t[2]) * 1000,
    iterate: parseInt(t[3]),
    salt: t[4],
    last: t[5],
  })
}

function verify(stored, password, cb) {
  if (typeof stored === "string") stored = unpack(stored)
  const ret = cycle(stored, password)
  if (ret.last === stored.last) return (cb(true, ret))
  return (cb(false, ret))
}

function packChallenge(conf) {
  const _fields = ['hash', 'expire', 'size', 'iterate', 'salt', 'sequence', 'control', 'response']

  var ret = '$POSPv1C'

  for (var a in _fields) {
    const k = _fields[a];
    if (conf.hasOwnProperty(k)) ret += `:${conf[k]}`
  }

  return (ret)
}

function unpackChallenge(stored) {
  const t = stored.split(":")
  const ret = {
    hash: t[1],
    expire: parseInt(t[2]),
    size: parseInt(t[3]),
    iterate: parseInt(t[4]),
    salt: t[5] ? t[5] : null,
    sequence: t[6] ? t[6] : null,
    control: t[7] ? t[7] : null,
    response: t[8] ? t[8] : null
  }
  return (ret)
}

/**
 * Generate a challenge (server-side)
 * @param {cb} cb - Callback(challenge)
 */
function generateChallenge(stored, opts, cb) {
  if (typeof stored === "string") stored = unpack(stored)
  opts = opts || {}
  opts.expire = opts.expire || 60

  var plain = new Date().getTime().toString();

  const ret = {
    hash: stored.hash,
    expire: Date.now() + (opts.expire * 1000),
    size: stored.size, // client indication
    iterate: stored.iterate, // client indication
    salt: stored.salt, // transmission salt
    sequence: _hash(system.xHash, jen.password(128, 128)) // sequence salt
  }

  // sign the server-side packet
  const hmac = crypto.createHmac(system.xHash, system.originSecret);
  hmac.update(`${ret.hash}:${ret.expire}:${ret.size}:${ret.iterate}:${ret.salt}:${ret.sequence}`);
  ret.control = hmac.digest("hex")

  cb(null, { packet: ret, string: packChallenge(ret) })
}


/**
 * Response to a challenge (client-side)
 * @param {cb} cb - Callback(challenge)
 */
function responseChallenge(stored, password, cb) {
  if (typeof stored === "string") stored = unpackChallenge(stored)

  const conf = {
    iterate: stored.iterate,
    size: stored.size,
    hash: stored.hash,
    salt: stored.salt
  }
  const c = cycle(conf, password)

  // compute response challenge
  const hmac = crypto.createHmac(system.xHash, c.last);
  hmac.update(`${stored.control}:${c.last}`);
  const ret = Object.assign({}, stored)
  ret.response = hmac.digest("hex")

  cb(null, { packet: ret, string: packChallenge(ret) })
}

function verifyChallenge(challenge, against, cb) {
  if (typeof challenge === "string") challenge = unpackChallenge(challenge)
  if (typeof against === "string") against = unpack(against)

  // verify control
  const hmacC = crypto.createHmac(system.xHash, system.originSecret);
  hmacC.update(`${challenge.hash}:${challenge.expire}:${challenge.size}:${challenge.iterate}:${challenge.salt}:${challenge.sequence}`);
  const control = hmacC.digest("hex")
  if (challenge.control !== control) {
    cb("Invalid challenge control")
    return;
  }

  // verify expiration
  const timeLim = Date.now() + (challenge.expire * 1000)
  if (Date.now() > challenge.expire) {
    cb("Challenge expired")
    return;
  }

  // self compute authentification key
  const hmacA = crypto.createHmac(system.xHash, against.last);
  hmacA.update(`${challenge.control}:${against.last}`);
  const response = hmacA.digest("hex")
  if (challenge.response !== response) {
    cb("Invalid challenge control")
    return;
  }

  cb(null)
}

module.exports = {
  generate,
  verify,
  generateChallenge,
  computeChallenge,
  responseChallenge,
  verifyChallenge,

  cycle,
  pack,
  unpack,
  packChallenge,
  unpackChallenge,
};
