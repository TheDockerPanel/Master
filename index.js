const config = require('../config.json');
const { exec } = require('child_process');
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

const isAdmin = async (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1]
    if(!token) {
        return res.status(401).send({ error: "Unauthorized" })
    }

    jwt.verify(token, app.config.jwt_secret, (error, user) => {
        if(error) {
            return res.status(401).send({ error: "Unauthorized" })
        }
        if(!user.admin) {
            return res.status(403).send({ error: "Unauthorized" })
        }
    })

    next()
}

app.post("/admin/create", isAdmin, async (req, res) => {
    const { username, password, admin, email} = req.body
    const allowedContainers = req.body.allowedContainers || app.config.default_allowed_containers
    if (!username || !password || !email || !admin ) return res.status(400).send("Missing fields")

    const payload = {username: username, password: bcrypt.hash(password, 10), admin: admin, email: email, allowedContainers: allowedContainers}
    
    let result = await app.db.users.findOne({username: username})    
    result = await app.db.users.findOne({email: email})
    if (result) return res.status(400).send("Email already in use.")

    result = await app.db.users.insertOne(payload)
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

app.listen(config.backPort, () => {
    console.log(`Backend server is running on port ${config.backPort}`);
})

app.