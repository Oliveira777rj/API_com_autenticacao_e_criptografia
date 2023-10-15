const jwt = require("jsonwebtoken");
require("dotenv").config();

const verifyToken = (req, res, next) => {
    function verifyToken(req, res, next){
        const bearerHeader = req.headers['authorization'];

        if(typeof bearerHeader !== 'undefined'){
            const bearerHeader = bearerHeader.split(" ")[1];
            req.roken = bearerHeader;
        }else{
            res.sendStatus(403)
        }

    }
}

module.exports = verifyToken