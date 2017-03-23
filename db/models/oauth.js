'use strict'; // eslint-disable-line semi

const app = require('APP')
const debug = require('debug')(`${app.name}:oauth`)
const Sequelize = require('sequelize')
const db = require('APP/db')
const User = require('./user')

const OAuth = db.define('oauths', {
  uid: Sequelize.STRING,
  provider: Sequelize.STRING,

  // OAuth v2 fields
  accessToken: Sequelize.STRING,
  refreshToken: Sequelize.STRING,

  // OAuth v1 fields
  token: Sequelize.STRING,
  tokenSecret: Sequelize.STRING,

  // The whole profile as JSON
  profileJson: Sequelize.JSON,
}, {
  // Further reading on indexes:
  // 1. Sequelize and indexes: http://docs.sequelizejs.com/en/2.0/docs/models-definition/#indexes
  // 2. Postgres documentation: https://www.postgresql.org/docs/9.1/static/indexes.html
	indexes: [{fields: ['uid'], unique: true}],
})

// OAuth.V2 is a default argument for the OAuth.setupStrategy method - it's our callback function that will execute when the user has successfully logged in
// On a separate note, we have also made this an `async` function as a teaching example. See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function. In `async` functions, we can `await` promises as if they were synchronous calls (but in reality they are still async!).
OAuth.V2 = async function (accessToken, refreshToken, profile, done) {
  // In async functions we can use normal `try`/`catch`. If any errors happen OR any `await`ed promises reject, we'll end up in the `catch` block.
  try {

    debug(profile)
    debug('provider:%s will log in user:{name=%s uid=%s}',
      profile.provider,
      profile.displayName,
      profile.id
    )

    // here we `await` the fulfillment value of a promise, which happens to be an array, and use deconstruction to assign the 0th element of that array to the variable `oauth`. This is like if we did `Oauth.findOrCreate(...).spread(oauth => {...})`
    const [oauth] = await OAuth.findOrCreate({
      where: {
        provider: profile.provider,
        uid: profile.id,
      }
    })

    // these lines do NOT run until the above `await` completes. It's written like synchronous code, except that this function is actually async – it allows the rest of your app to run while the above `await` is pending!
    oauth.profileJson = profile
    oauth.accessToken = accessToken

    // another `await` call which gets an array of results and assigns the 0th element to the variable `user`. Here we use `Promise.all` to do two parallel independent actions — fetching a user and saving an instance. We only need the returned data from the first promise, but we don't want to proceed until both complete.
    const [user] = await Promise.all([oauth.getUser(), oauth.save()])

    // If we already have this user we can call the Passport `done` function. The `return` on this line is just used to stop the function early. Control flow logic is much easier to reason about inside of `async` functions than promise chains. :-)
    if (user) return done(null, user)

    // If this user is logging in for the first time, we need to first create them and then associate the oauth instance with them. We can do this with two `await`s in sequence – exactly like multiple `.then`s chained together.
    const createdUser = await User.create({
      name: profile.displayName,
    })
    await oauth.setUser(createdUser)

    // once both of the above `await`s complete (in series), we can call the Passport `done` callback.
    done(null, createdUser)

  } catch (err) {
    // if any error occurs or any promise rejects, let Passport know about it.
    done(err)
  }
}

// setupStrategy is a wrapper around passport.use, and is called in authentication routes in server/auth.js
OAuth.setupStrategy =
({
  provider,
  strategy,
  config,
  oauth = OAuth.V2,
  passport
}) => {
  const undefinedKeys = Object.keys(config)
        .map(k => config[k])
        .filter(value => typeof value === 'undefined')
  if (undefinedKeys.length) {
    for (let key in config) {
      if (!config[key]) debug('provider:%s: needs environment var %s', provider, key)
    }
    debug('provider:%s will not initialize', provider)
    return
  }

  debug('initializing provider:%s', provider)

  passport.use(new strategy(config, oauth)) // eslint-disable-line new-cap
}

module.exports = OAuth
