/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                         *
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *
 *                                                                         *
 *  2018 - Michael VERGOZ                                                  *
 *  All Rights Reserved.                                                   *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

const crypto = require('crypto');
const jen = require("node-jen")();
const EC = require('elliptic').ec;

const allowedHashes = {
  sha256: 32,
  sha512: 64
}

const system = {
  originSecret: jen.password(128, 128),
  hash: "sha256"
}

function paramter(system) {

}

class lpCryptoPOSP {

  /**
   * Signing instance
   * @param {lpCrypto} root - Lockypass crypto context
   * @constructor
   */
  constructor(options) {
    // this.salt = root.config.pos.salt || jen.password(128, 128);
    // this.iterate = root.config.pos.iteration || 250000; // gives ~15Mo on sha256
    // this.hash = root.config.pos.hash || "sha256";
    // this.encoding = root.config.pos.encoding || "hex";

    // // generate ephemeral EC DSA key for challenge
    // this.dsa = new EC(config.DSAcurve);
    // this.key = this.dsa.genKeyPair();

    // // all prefixes
    // var version = "$LPPPv1";
    // this.prefix = {
    // 	password: version,
    // 	challenge: version+"-C",
    // 	challengeResponse: version+"-CR",
    // }

    // // copy back config
    // root.config.pos.salt = this.salt;
    // root.config.pos.iteration = this.iterate;
    // root.config.pos.hash = this.hash;
    // root.config.pos.encoding = this.encoding;

    // console.log("iteration="+this.iterate);
    // console.log("proof of space="+(this.iterate*64/1000/1000)+'Mo');
    // console.log("salt="+this.salt);
    // console.log("hash="+this.hash);
    // console.log("encoding="+this.encoding);
    // console.log("challenge DSA="+this.key.getPublic().encode('hex'));

    if (allowedHashes[options.hash] === true) this._sHash = options.hash
    else this._sHash = "sha256"
  }

  _hash(d) {
    const h = crypto.createHash(this._sHash)
    h.update(d)
    return (h.digest("hex"))
  }

  /**
   * Generate POSP from plain password (both side)
   * @param {password} password - Plain password
   * @param {cb} cb - Callback(posPassword)
   */
  generate(password, cb, opts) {
    opts = opts || {}
    opts.iterate = opts.iterate || 4
    opts.size = opts.size || 3 * 1000 * 1000
    if (allowedHashes[opts.hash] > 0) opts.hash = "sha256"
    const conf = {
      iterate: opts.iterate,
      size: opts.size,
      hash: opts.hash,
      salt: this._hash(jen.password(128, 128))
    }
    const ret = this.cycle(conf, password)
    cb(ret)
  }


  /**
   * Compute a challenge (client-side)
   * @param {password} password - Password provided by generate() computed from client-side
   * @param {seed} seed - Challenge received from server
   * @param {cb} cb - Callback(challengeResponse)
   */
  computeChallenge(password, seed, cb) {
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

  cycle(conf, password) {
    const ret = { conf, size: 0, blocks: 0 }
    const startedAt = Date.now()
    const series = [];

    var last = conf.salt;
    const showMeYouHaveTheRest = (block, pos) => {
      var last = block;
      for (var a = pos; a < series.length; a++) {
        const toHash = last + series[pos] + conf.salt + password
        const hashed = this._hash(toHash)
        last = hashed;
      }
      return (last);
    }

    // pass 1 - create initial blockchain
    do {
      const toHash = last + conf.salt + password;
      const hashed = this._hash(toHash);
      series.push(hashed); ret.blocks++;

      last = hashed;
      ret.size += hashed.length;

    } while (ret.size < conf.size)

    // pass 2 - proove the space of series
    for (var a = conf.iterate - 1; a >= 0; a--) {
      const pos = series[a];
      const rest = showMeYouHaveTheRest(last, a);
      const toHash = last + pos + conf.salt + password + rest
      const hashed = this._hash(toHash)

      series.push(hashed); ret.blocks++; // outch

      ret.size += hashed.length;
      last = hashed;
    }

    ret.time = Date.now() - startedAt
    ret.string = this.pack(conf, last)
    ret.last = last;
    return (ret)
  }

  pack(conf, last) {
    return (`$POSPv1:${this._sHash}:${conf.size / 1000}:${conf.iterate}:${conf.salt}:${last}`)
  }

  unpack(stored) {
    const t = stored.split(":")
    return ({
      hash: t[1],
      size: parseInt(t[2]) * 1000,
      iterate: parseInt(t[3]),
      salt: t[4],
      last: t[5],
    })
  }

  verify(stored, password, cb) {
    if (typeof stored === "string") stored = this.unpack(stored)
    const ret = this.cycle(stored, password)
    if (Buffer.compare(ret.last, stored.last) === 0) return (cb(true, ret))
    return (cb(false, ret))
  }

  packChallenge(conf) {
    const _fields = ['hash', 'expire', 'size', 'iterate', 'salt', 'sequence', 'control', 'response']

    var ret = '$POSPv1C'

    for (var a in _fields) {
      const k = _fields[a];
      if (conf.hasOwnProperty(k)) ret += `:${conf[k]}`
    }

    return (ret)
  }

  unpackChallenge(stored) {
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
  generateChallenge(stored, opts, cb) {
    if (typeof stored === "string") stored = this.unpack(stored)
    opts = opts || {}
    opts.expire = opts.expire || 60

    var plain = new Date().getTime().toString();

    const ret = {
      hash: stored.hash,
      expire: Date.now() + (opts.expire * 1000),
      size: stored.size, // client indication
      iterate: stored.iterate, // client indication
      salt: stored.salt, // transmission salt
      sequence: this._hash(jen.password(128, 128)) // sequence salt
    }

    // sign the server-side packet
    const hmac = crypto.createHmac(system.hash, system.originSecret);
    hmac.update(`${ret.hash}:${ret.expire}:${ret.size}:${ret.iterate}:${ret.salt}:${ret.sequence}`);
    ret.control = hmac.digest("hex")

    cb({ packet: ret, string: this.packChallenge(ret) })
  }


  /**
   * Response to a challenge (client-side)
   * @param {cb} cb - Callback(challenge)
   */
  responseChallenge(stored, password, cb) {
    if (typeof stored === "string") stored = this.unpackChallenge(stored)

    const conf = {
      iterate: stored.iterate,
      size: stored.size,
      hash: stored.hash,
      salt: stored.salt
    }
    const cycle = this.cycle(conf, password)

    // compute response challenge
    const hmac = crypto.createHmac(system.hash, cycle.last);
    hmac.update(`${stored.control}:${cycle.last}`);
    const ret = Object.assign({}, stored)
    ret.response = hmac.digest("hex")

    cb({ packet: ret, string: this.packChallenge(ret) })
  }

  verifyChallenge(challenge, against, cb) {
    if (typeof challenge === "string") challenge = this.unpackChallenge(challenge)
    if (typeof against === "string") against = this.unpack(against)

    // verify control
    const hmacC = crypto.createHmac(system.hash, system.originSecret);
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
    const hmacA = crypto.createHmac(system.hash, against.last);
    hmacA.update(`${challenge.control}:${against.last}`);
    const response = hmacA.digest("hex")
    if (challenge.response !== response) {
      cb("Invalid challenge control")
      return;
    }

    cb(null)
  }
}

module.exports = lpCryptoPOSP;
