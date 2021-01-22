/*
 * Issue #1
 */
const posp = require('../index')

const global = {}

function shot(name, init) {
  describe(name, function () {
    it('Initializing test context', init)

    // todo
    it('Check if server secret has effect', function (done) {
      done()
    })

    it('Generate POSP password', function (done) {
      this.timeout(4000);
      posp.generate("Super password", (err, res) => {
        // if(!res.conf.hash) return(done("No hash specified"))
        // console.log("generate", res)
        global.passStored = res.string;
        done()
      })
    })

    it('Verify with good password', function (done) {
      this.timeout(4000);
      posp.verify(global.passStored, "Super password", (authed, res) => {
        if (authed !== true) done("Passwords are egal")
        else done()
      })
    })

    it('Verify with wrong password', function (done) {
      this.timeout(4000);
      posp.verify(global.passStored, "Not good", (authed, res) => {
        if (authed === true) done("Passwords must be different")
        else done()
      })
    })

    it('Generate server-side authentification challenge', function (done) {
      posp.generateChallenge(global.passStored, {}, (err, res) => {
        if (!res.hasOwnProperty("packet")) return (done("Invalid packet"))
        if (!res.hasOwnProperty("string")) return (done("Invalid string"))
        global.serverChallenge = res.string;
        // console.log("generate challenge", res)
        done()
      })
    })

    it('Client response to a server authentification challenge', function (done) {
      this.timeout(4000);
      posp.responseChallenge(global.serverChallenge, "Super password", (err, res) => {
        global.clientChallengeResponse = res.string;
        // console.log('challenge response', global.serverChallenge, res)
        done()
      })
    })

    it('Server verify client response challenge', function (done) {
      posp.verifyChallenge(global.clientChallengeResponse, global.passStored, (err) => {
        if (err) return (done(err))
        done()
      })
    })
  })
}

shot('Using default configuration', (done) => {
  posp.configure()
  done()
})

shot('Defaulting to SHA512 for POS', (done) => {
  posp.configure({
    posHash: "sha512"
  })
  done()
})

shot('Defaulting to SHA512 for POS & exchange', (done) => {
  posp.configure({
    xHash: "sha512",
    posHash: "sha512"
  })
  done()
}) 