/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                         *
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *
 *                                                                         *
 *  2018 - Michael VERGOZ                                                  *
 *  All Rights Reserved.                                                   *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

const crypto = require('crypto');

const hashesConfig = {
  sha256: {
    iterate: 10,
    size: 1 * 1000 * 1000
  },
  sha512: {
    iterate: 10,
    size: 2 * 1000 * 1000
  },
}

const system = {
  secret: null,
  xHash: "sha256", // exchange hash
  posHash: "sha256", // proof of space hash,

  randomBytes: (size) => {
    // const crypto = require('crypto');
    return (crypto.randomBytes(size).toString("hex"))
  },

  hash: (algo, d) => {
    // const crypto = require('crypto');
    const h = crypto.createHash(algo)
    h.update(d)
    return (h.digest("hex"))
  },

  hmac: (algo, secret, d) => {
    // const crypto = require('crypto');
    const hmac = crypto.createHmac(algo, secret);
    hmac.update(d);
    return (hmac.digest("hex"))
  }
}


function configure(input) {
  if (!input) input = {}

  if (input.hasOwnProperty("secret")) {
    system.secret = input.secret;
  }

  if (input.hasOwnProperty("xHash") && typeof hashesConfig[input.xHash] === "object") {
    system.xHash = input.xHash;
  }

  if (input.hasOwnProperty("posHash") && typeof hashesConfig[input.posHash] === "object") {
    system.posHash = input.posHash;
  }

  // generate random secret
  if (!system.secret) system.secret = system.randomBytes(128)

  return (system)
}

/**
 * Generate POSP from plain password (both side)
 * @param {password} password - Plain password
 * @param {cb} cb - Callback(posPassword)
 */
function generate(password, cb, opts) {
  opts = opts || {}

  if (typeof hashesConfig[opts.hash] !== "object") opts.hash = system.posHash
  const pH = hashesConfig[opts.hash];

  opts.iterate = opts.iterate || pH.iterate
  opts.size = opts.size || pH.size
  const conf = {
    iterate: opts.iterate,
    size: opts.size,
    hash: opts.hash,
    salt: system.hash(opts.hash, system.randomBytes(128))
  }
  const ret = cycle(conf, password)
  cb(null, ret)
}


/**
 * Verify a password (server & client side)
 * @param {stored} passStored - Stored password string or object
 * @param {password} string - Plaintext password
 * @param {cb} cb - Callback(authed, challenge)
 */
function verify(stored, password, cb) {
  if (typeof stored === "string") stored = unpack(stored)
  const ret = cycle(stored, password)
  if (ret.last === stored.last) return (cb(true, ret))
  return (cb(false, ret))
}

/**
 * Generate a challenge (server-side)
 * @param {stored} passStored - Stored password string or object
 * @param {opts} challengeOptions - Challenge options
 * @param {cb} cb - Callback(error, challenge)
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
    sequence: system.hash(system.xHash, system.randomBytes(128)) // sequence salt
  }

  // sign the server-side packet
  ret.control = system.hmac(
    system.xHash,
    system.secret,
    `${ret.hash}:${ret.expire}:${ret.size}:${ret.iterate}:${ret.salt}:${ret.sequence}`
  )

  cb(null, { packet: ret, string: packChallenge(ret) })
}


/**
 * Response to a challenge (client-side)
 * @param {stored} stored - Stored challenge response (can be unpacked)
 * @param {password} password - Plain text password
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
  const ret = Object.assign({}, stored)
  ret.response = system.hmac(
    system.xHash,
    c.last,
    `${stored.control}:${c.last}`
  )

  cb(null, { packet: ret, string: packChallenge(ret) })
}

function verifyChallenge(challenge, against, cb) {
  if (typeof challenge === "string") challenge = unpackChallenge(challenge)
  if (typeof against === "string") against = unpack(against)

  // verify control
  const control = system.hmac(
    system.xHash,
    system.secret,
    `${challenge.hash}:${challenge.expire}:${challenge.size}:${challenge.iterate}:${challenge.salt}:${challenge.sequence}`
  )
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
  const response = system.hmac(
    system.xHash,
    against.last,
    `${challenge.control}:${against.last}`
  )
  if (challenge.response !== response) {
    cb("Invalid challenge control")
    return;
  }

  cb(null)
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
      const hashed = system.hash(conf.hash, toHash)
      last = hashed;
    }
    return (last);
  }

  const drainBlockchain = (seed) => {
    ret.size = 0;
    do {
      const toHash = `${seed}:${last}:${conf.salt}:${password}`;
      const hashed = system.hash(conf.hash, toHash);
      series.push(hashed); ret.blocks++;
  
      last = hashed;
      ret.size += hashed.length;
  
    } while (ret.size < conf.size)
  }

  // pass 1 - initial blockchain: proof of space
  drainBlockchain("POSPv1")

  // pass 2 - proof of iteration
  // this pass will make a hash of the checksum of the blockchain
  // then this hash will be diluted in the blockchain which will 
  // be completely rebuilt.
  // at each iteration a proof of space is asked to the showMeYouHaveTheRest 
  // function which must browse the memory aloccated by the computer.
  for (var a = conf.iterate - 1; a >= 0; a--) {
    const pos = series[a];
    const rest = showMeYouHaveTheRest(last, a);
    const toHash = `${last}:${pos}:${conf.salt}:${password}:${rest}`;
    const hashed = system.hash(conf.hash, toHash)

    // here we dilute the hash in a new blockchain
    drainBlockchain(hashed)
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


module.exports = {
  generate,
  verify,
  generateChallenge,
  responseChallenge,
  verifyChallenge,
  configure,

  cycle,
  pack,
  unpack,
  packChallenge,
  unpackChallenge,
};
