/*
 * Issue #1
 */
const posp = require('../index')

var globalHdl
var globalStored

const global = {}

describe('General', function () {
  it('creating posp instance', function (done) {
    globalHdl = new posp({})
    done()
  })

  it('Generate POSP password', function (done) {
    this.timeout(4000);
    globalHdl.generate("Super password", (res) => {
      // console.log("generate", res)
      globalStored = res.string;
      done()
    })
  })

  // it('Verify with good password', function (done) {
  //   this.timeout(4000);
  //   globalHdl.verify(globalStored, "Super password", (res) => {
  //     if(res !== true) done("Passwords are egal")
  //     else done()
  //   })
  // })

  // it('Verify with wrong password', function (done) {
  //   this.timeout(4000);
  //   globalHdl.verify(globalStored, "Not good", (res) => {
  //     if(res === true) done("Passwords must be different")
  //     else done()
  //   })
  // })


  it('Generate server-side authentification challenge', function (done) {
    globalHdl.generateChallenge(globalStored, {}, (res) => {
      if(!res.hasOwnProperty("packet")) return(done("Invalid packet"))
      if(!res.hasOwnProperty("string")) return(done("Invalid string"))
      global.serverChallenge = res.string;
      // console.log(res)
      done()
    })
  })

  it('Client response to a server authentification challenge', function (done) {
    this.timeout(4000);
    globalHdl.responseChallenge(global.serverChallenge, "Super password", (res) => {
      global.clientChallengeResponse = res.string;
      // console.log('challenge response', global.serverChallenge, res)
      done()
    })
  })

  it('Server verify client response challenge', function (done) {
    globalHdl.verifyChallenge(global.clientChallengeResponse, globalStored, (err) => {
      if(err) return(done(err))
      // console.log('verify response', err)
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
