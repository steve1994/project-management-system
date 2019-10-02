var express = require('express');
var router = express.Router();
var bcrypt = require('bcrypt');
const saltRounds = 10;

module.exports = (pool) => {

    router.get('/', function(req, res) {
        res.render('index');
    });

    router.post('/', function(req, res) {
        let email = req.body.email;
        let password = req.body.password;
        let sql = "SELECT * FROM users WHERE email = $1";
        pool.query(sql, [email], (err,response) => {
            if (err) throw err;
            if (response.rows.length > 0) {
                bcrypt.compare(password,response.rows[0].password,function (err,valid) {
                    if (valid) {
                        req.session.user = response.rows[0];
                        res.redirect('/projects');
                    } else {
                        res.redirect('/');
                    }
                })
            } else {
                res.redirect('/');
            }
        })
    });

    router.get('/signout', function (req, res) {
        req.session.destroy(function (err) {
            if (err) throw err;
            res.redirect('/');
        })
    })

    return router;

}
