/*
 * Issue #1
 */
const posp = require('../index')


var globalStored

const global = {}

describe('General', function () {

  it('Generate POSP password', function (done) {
    this.timeout(4000);
    posp.generate("Super password", (err, res) => {
      // if(!res.conf.hash) return(done("No hash specified"))
      console.log("generate", res)
      globalStored = res.string;
      done()
    })
  })

  it('Verify with good password', function (done) {
    this.timeout(4000);
    posp.verify(globalStored, "Super password", (authed, res) => {
      if (authed !== true) done("Passwords are egal")
      else done()
    })
  })

  it('Verify with wrong password', function (done) {
    this.timeout(4000);
    posp.verify(globalStored, "Not good", (authed, res) => {
      if (authed === true) done("Passwords must be different")
      else done()
    })
  })

  it('Generate server-side authentification challenge', function (done) {
    posp.generateChallenge(globalStored, {}, (err, res) => {
      if(!res.hasOwnProperty("packet")) return(done("Invalid packet"))
      if(!res.hasOwnProperty("string")) return(done("Invalid string"))
      global.serverChallenge = res.string;
      console.log("generate challenge", res)
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
    posp.verifyChallenge(global.clientChallengeResponse, globalStored, (err) => {
      if(err) return(done(err))
      done()
    })
  })

  // considering the user already match a POSPv1 string
  // the server will generate a challenge for the user
  // it('Generate POSP client challenge', function (done) {
  //   this.timeout(4000);
  //   globalHdl.generate("Super password", (res)=> {
  //     globalStored = res.string;
  //     console.log(res)
  //     done()
  //   })

  // })
})
