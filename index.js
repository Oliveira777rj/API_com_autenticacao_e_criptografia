const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const login = require("./middleware/verifyToken");
require("dotenv").config();
const verifyToken = require("./middleware/verifyToken")

app.set("view engine", "ejs");

//database
const mysql = require("mysql");
const conn = mysql.createConnection({
    user: process.env.DB_USER,
    host:process.env.DB_HOST,
    password:process.env.DB_PASSWORD,
    database:process.env.DB_DATABASE
});

app.use(express.json());

app.get("/", (req, res) => {
    res.render("./views/index");
});

app.post("/api/register", (req, res, next) => {
    const {name, email, password} = req.body;

    if(!name){
        return res.json({ msg : "O nome é obrigatório!"}).status(402);
    }
    if(!email){
        return res.json({ msg : "O e-mail é obrigatório!"}).status(402);
    }
    if(!password){
        return res.json({ msg : "A senha é obrigatório!"}).status(402);
    }

    const query = "INSERT INTO users (`name`, `email`, `password`) VALUES (?)";
    bcrypt.hash(password, 6, (err, bcryptHash) => {

        if(err){
            res.json("erro de criptografia" + err).status(401);
            return
        }
        const values = [
            name,
            email,
            bcryptHash
        ]
        conn.query(query, [values], (err, data) => {
            if(err){
                res.json("Erro no cadastro de usuário" + err).status(401);
                return;
            }
            res.json("Usuário cadastrado com sucesso!").json(data).status(201);
            return;
        });
    });
});

app.get("/api/login", (req, res, next) => {

    const { email, password } = req.body;

    if(!email){
        return res.json({ msg : "O e-mail é obrigatório!"}).status(402)
    }
    if(!password){
        return res.json({ msg : "A senha é obrigatório!"}).status(402)
    }

    const query = "SELECT * FROM users WHERE email = (?)";
    conn.query(query, [email], (err, result) => {

        if(err){
            return res.json({ msg : err }).status(400);
        }
        if(!result.length){
            return res.json({ msg : "E-mail ou senha incorreta" }).status(400);
        }
        bcrypt.compare(password, result[0]["password"], (bcryptErro, bcryptResult) => {
            if(bcryptErro){
                return res.json({ msg : bcryptErro });
            }
            if(bcryptResult){
                const token = jwt.sign({ result }, process.env.SECRET_KEY, { expiresIn:'2h' })
                return res.cookie({ token }).redirect("message");
            }
        })
        return res.json({ msg : "E-mail ou senha incorreta" }).status(400);
    })
});

app.post("/api/user", verifyToken, (req, res, next) => {
    jwt.verify(req.token, process.env.SECRET_KEY, (err, authData) => {
        if(err){    
            res.json(err).status(403);
        }else {
            res.json({ msg : "Autenticado com sucesso" })
        }
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log("Server running on port " + PORT)
});