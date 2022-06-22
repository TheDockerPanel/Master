const config = require('../config.json');
const jwt = require("jsonwebtoken")
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb')
const express = require('express');

const app = express()
app.use(express.json())

app.config = config
app.db = MongoClient(config.mongoUrl, { useNewUrlParser: true })

app.db.epikpanel = app.db.db('epikpanel')
app.db.users = app.db.epikpanel.collection('users')
app.db.containers = app.db.epikpanel.collection("containers")

const generateId = length => {
    let n = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    let password = "";
    
    while (password.length < length) {
        password += n[Math.floor(Math.random() * n.length)];
    }

    return password; // Thanks Rin.
}

const getUser = async (req, res) => {
    jwt.verify(req.headers.authorization.split(" ")[1], app.config.jwt_secret, (error, user) => {
        if(error) {
            return res.status(401).send({ error: "Unauthorized" })
        } else if(!await app.db.users.findOne({ email: user.email })) {
            return res.status(403).send({ error: "Unauthorized" })
        }
        return user
    })

}

const isLoggedIn = async (req, res, next) => {

    const token = req.headers.authorization && req.headers.authorization.split(" ")[1]

    if(!token) {
        return res.redirect(401, "/auth/login")
    }

    await getUser(req, res)

    next()
}

const isAdmin = async (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1]
    if(!token) {
        return res.status(401).send({ error: "Unauthorized" })
    }

    const user = await getUser(req, res)

    if(!user.admin) {
        return res.status(403).send({ error: "Unauthorized" })
    }

    next()
}

app.post("/admin/create", isAdmin, async (req, res) => {
    const { username, password, admin, email} = req.body
    const allowedContainers = req.body.allowedContainers || app.config.default_allowed_containers
    if (!username || !password || !email || !admin ) return res.status(400).send("Missing fields")
    
    const existingResults = await app.db.users.findOne({username: username})    
    existingResults = await app.db.users.findOne({email: email})
    if (existingResults) return res.status(400).send("Email already in use.")

    const payload = {username: username, password: bcrypt.hash(password, 10), admin: admin, email: email, allowedContainers: allowedContainers}

    await app.db.users.insertOne(payload)
    return res.status(201).send()  
})

app.post("/auth/login", async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) return res.status(400).send("Missing fields")

    let result = await app.db.users.findOne({username: username})
    if (!result) return res.status(401).send("Username not found/Invalid password.")
    if (!await bcrypt.compare(password, result.password)) return res.status(401).send("Username not found/Invalid password.")

    const token = jwt.sign({username: result.username, admin: result.admin, allowedContainers: result.allowedContainers}, app.config.jwt_secret)
    return res.status(200).send({token: token})
})

app.post("/auth/signup", async (req, res) => {
    const { username, password, email } = req.body
    const allowedContainers = req.body.allowedContainers || app.config.default_allowed_containers
    if (!username || !password || !email) return res.status(400).send("Missing fields")
    for(field of ["username", "email"]) {
        const result = await app.db.users.findOne({[field]: req.body[field]})
        if(result) return res.status(400).send(`${field} already in use.`)
    }
    const payload = {username: username, password: bcrypt.hash(password, 10), email: email, allowedContainers: allowedContainers}
    await app.db.users.insertOne(payload)
    return res.redirect(201, "/auth/login")
})

app.get("/containers", isLoggedIn, async (req, res) => {
    const user = await getToken(req, res)
    const containers = await app.db.containers.find(container => container.ownerEmail == user.email)
    return res.status(200).send(containers)
})

app.post("/containers/", isLoggedIn, async (req, res) => {

    const user = await getToken(req, res)
    const { name, image, owner } = req.body

    if (!name || !image || !owner) return res.status(400).send("Missing fields")


    const payload = {name: name, image: image, owner: owner, id: generateId(30)}
    const containers = await app.db.containers.find(container => container.ownerEmail == user.email)

    if(containers.length == user.allowedContainers) return res.status(400).send("You have reached the maximum number of containers.") // If the user has reached the maximum number of containers

    await app.db.containers.insertOne(payload)
    res.status(201).send()    
})

app.get("/containers/:id", isLoggedIn, async (req, res) => {
    const containerId = req.params.id
    const user = await getToken(req, res)
    const container = await app.db.containers.findOne({id: containerId, ownerEmail: user.email})
    if(!container) return res.status(404).send("Container not found.")
    return res.status(200).send(container)
})

app.delete("/containers/:id", isLoggedIn, async (req, res) => {
    const containerId = req.params.id
    const user = await getToken(req, res)
    const container = await app.db.containers.findOne({id: containerId, ownerEmail: user.email})
    if(!container) return res.status(404).send("Container not found.")
    await app.db.containers.deleteOne({id: containerId, ownerEmail: user.email})
    return res.status(204).send()
})

app.listen(config.backPort, () => {
    console.log(`Backend server is running on port ${config.backPort}`);
})