/* imports */
require('dotenv').config()
const express = require('express')
const mongoose = require("mongoose")
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//Config JSON response
app.use(express.json())

//Models
const User = require('../models/User')


const TOKEN = process.env.SERVER_TOKEN

// Public Route
app.get('/', (req, res) => {
    res.status(200).json({msg: 'Sejam Bem-Vindos a nossa API!'})
})

// Register
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body


    switch (true) {
        case !name:
            return res.status(422).json({ msg: "O nome é obrigatório!" });
        case !email:
            return res.status(422).json({ msg: "O email é obrigatório!" });
        case !password:
            return res.status(422).json({ msg: "A senha é obrigatória!" });
        case password !== confirmpassword:
            return res.status(422).json({ msg: "As senhas não conferem!" });
        // Adicione outras validações conforme necessário
        default:
            break;
    }

    // check user of exist
    const userExist = await User.findOnde({ email: email })

    if(userExist) {
        return res.status(422).json({ msg: "Por Favor, utilize outro email!" });
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password
    })

    try{
        await user.save()

        res.status(201).json({ msg: "Usuário criando com sucesso!" })
    }
    catch(error) {
        console.log(error)

        res.status(500)
        .json({
            msg: "Aconteceu um erro no servidor, tente mais tarde!"
        })
    }

    res.status(201).json({ msg: "Usuário registrado com sucesso!" });

})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASSWORD

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.qerdcas.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        app.listen(TOKEN, () => {
            console.log('Server Runing...')
        })
    })
    .catch((err) => console.log(err))