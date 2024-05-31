/* imports */
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

//Config JSON response
app.use(express.json());

//Models
const User = require("../models/User");

const TOKEN = process.env.SERVER_TOKEN;

// Public Route
app.get("/", (req, res) => {
    res.status(200).json({ msg: "Sejam Bem-Vindos a nossa API!" });
});

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id

    // check if user exists
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: "usuario não encontrado!" });
    }

    if (user) {
        return res.status(200).json({ user });
    }
})


function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({ msg: 'Acesso negado!'})
    }

    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    } catch(err) {
        console.log(err)
        res.status(400).json({ msg: "Token Invalido!" })
    }
}

// Register
app.post("/auth/register", async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;

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
    const userExist = await User.findOne({ email: email });

    if (userExist) {
        return res.status(422).json({ msg: "Por Favor, utilize outro email!" });
    }

    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    });

    try {
        await user.save();

        res.status(201).json({ msg: "Usuário criando com sucesso!" });
    } catch (error) {
        console.log(error);

        res.status(500).json({
            msg: "Aconteceu um erro no servidor, tente mais tarde!",
        });
    }

    res.status(201).json({ msg: "Usuário registrado com sucesso!" });
});

// Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    // Validations

    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório!" });
    }
    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória!" });
    }

    // check user of exist
    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(404).json({ msg: "usuario não encontrado!" });
    }

    // check is password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha Inválida!" });
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret
        );
        return res.status(200).json({
            msg: "Autenticação realizada com sucesso!", token
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({
            msg: "AutntiAconteceu um erro no servidor, tente novamente mais tarde!",
        });
    }
});

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}@cluster0.qerdcas.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
    )
    .then(() => {
        app.listen(TOKEN, () => {
            console.log("Server Runing...");
        });
    })
    .catch((err) => console.log(err));
