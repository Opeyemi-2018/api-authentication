// Importing required modules
let express = require('express') // Importing Express framework
let Datastore = require('nedb-promises') // Importing NeDB for database operations
let bcrypt = require('bcryptjs') // Importing bcrypt for password hashing
let jwt = require('jsonwebtoken') // Importing jsonwebtoken for authentication
let config = require('./config.js') // Importing custom configuration file

// Initializing Express application
let app = express()

// Middleware to parse JSON requests
app.use(express.json())

// Creating or loading users datastore
let users = Datastore.create('User.db')

// Route for homepage
app.get('/', (req, res) => {
    res.send("authentication") // Sending response for homepage route
})

// Route for user registration
app.post('/api/auth/reg', async (req, res) => {
    try {
        // Extracting name, email, and password from request body
        let {name, email, password, role } = req.body
        // Validating if all required fields are provided
        if(!name || !email || !password){
            return res.status(422).json({msg: 'please fill in all fields'}) // Sending error response if any field is missing
        }

        // Checking if the email already exists in the database
        if(await users.findOne({email})){
            return res.status(409).json({msg: 'email already exist'}) // Sending error response if email already exists
        }
        // Hashing the password before storing it in the database
        let hashedPassword = await bcrypt.hash(password, 10)

        // Inserting new user data into the database
        let newUser = await users.insert({
            name, 
            email,
            password: hashedPassword, // Storing hashed password
            // role: role ?? "member"
        })
        // Sending success response with user ID upon successful registration
        return res.status(201).json({msg: 'registered succcessfully', id: newUser._id})

    } catch (error) {
        // Sending error response if any unexpected error occurs
        return res.status(500).json({msg: error.msg})
    }
})

app.post('/api/auth/login', async (req, res) => {
    try {
        let {email, password} = req.body // We're checking the message we received for the email and secret code.

        if(!email || !password){
            return res.status(422).json({msg: 'please fill in all fields'}) // If the email or secret code is missing, we say "Hey, you forgot 
            //something!"
        }

        let user = await users.findOne({email}) // We're looking in our special box to find the person with the email we got.

        if(!user){
            return res.status(401).json({msg: 'email or password is invalid'}) // If we can't find them, we say "Hmm, we don't know you."
        }

        let passwordMatch = await bcrypt.compare(password, user.password) // We're checking if the secret code matches the one we wrote down.

        if(!passwordMatch){
            return res.status(422).json({msg: 'email or password is invalid'}) // If the secret code doesn't match, we say "That's not the right code."
        }
        let accessToken = jwt.sign({userID: user._id}, config.accessTokenSecret, {subject: 'accessApi', expiresIn: '1h'}) // If everything is
        // correct, we give them a special stamp to say "You're allowed in!"

        // let refreshToken = jwt.sign({user: user._id}, )

        return res.status(200).json({id: user._id, // We tell them their special number.
            name: user.name, // We tell them their name.
            email: user.email, // We remind them of their email.
            accessToken // We give them the special stamp.
        })      
    } catch (error) {
        // If something unexpected happens, we don't do anything for now.
    }
})

// This endpoint retrieves information about the currently logged-in user.
app.get("/api/users/current", ensureAuthenticated, async (req, res) => {
    try {
        // Finding the user in the database using their ID extracted from the authentication token.
        let user = await users.findOne({_id:  req.user.id})

        // Sending back the user's information if found.
        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email 
        })
    } catch (error) {
        // Handling any errors that might occur during the process.
        return res.status(500).json({msg: error.msg})
    }
})

// Middleware function to ensure that the request is authenticated.
async function ensureAuthenticated(req, res, next){
    // Extracting the access token from the request headers.
    let accessToken = req.headers.authorization

    // Checking if the access token is missing.
    if(!accessToken){
        return res.status(401).json({msg: "Access token not found"})
    }

    try {
        // Verifying the access token to ensure it's valid and not expired.
        let decodedToken = jwt.verify(accessToken, config.accessTokenSecret)

        // Storing the user ID extracted from the token in the request object for later use.
        req.user = {id: decodedToken.user}
        
        // Proceeding to the next middleware or route handler.
        next()

    } catch (error) {
        // Handling any errors related to invalid or expired tokens.
        return res.status(401).json({msg: "Access token invalid or expired"})
    }
}

app.get('/api/admin', ensureAuthenticated, authorize(['admin']), (req, res) =>{
    return res.status(200).json({msg: 'only aadmin can acess this route'})
})

function authorize(role = []){
    return async function (req, res, next){
        let user = await users.findOne({_id: req.user.id})

        if(!user || !role.includes(user.role)){
            return res.status(403).json({msg: 'access denied'})
        }

        next()
    }
}

app.get('/api/moderators', ensureAuthenticated, authorize(['admin', 'moderator']), (req, res) =>{
    return res.status(200).json({msg: 'only admins and moderators can acess this route'})
})

app.listen(4000, console.log('app is listening to port 3000'))
//44