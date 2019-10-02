var express = require('express');
var router = express.Router();
var helper = require('../helper/utils');
var bcrypt = require('bcrypt');
const saltRounds = 10;

function convertToString(setColumns) {
    let stringConditional = "";
    for (let i=0;i<setColumns.length;i++) {
        stringConditional += setColumns[i];
        if ((i < setColumns.length-1) && (setColumns[i] != "")) {
            stringConditional += ",";
        }
    }
    return stringConditional;
}

function buildUpdateQuery(columnsConditional) {
    let setColumns = [];
    setColumns[0] = (columnsConditional[0] == "") ? '' : 'password = $';
    setColumns[1] = 'firstname = $';
    setColumns[2] = 'lastname = $';
    setColumns[3] = 'role = $';
    setColumns[4] = 'isfulltime = $';
    setColumns[5] = 'fullname = $';
    let counter = 1;
    for (let i=0;i<setColumns.length;i++) {
        if (setColumns[i] != "") {
            setColumns[i] += counter;
            counter++;
        }
    }
    return [counter,convertToString(setColumns)];
}

function buildUpdateQueryValues(columnsConditional) {
    let valueConditional = [];
    // SETTING FOR COLUMN PASSWORD, FIRSTNAME, LASTNAME
    for (let i=0;i<columnsConditional.length;i++) {
        if (i == 4) {
            valueConditional.push(columnsConditional[i]);
        } else {
            if (columnsConditional[i] != "") {
                valueConditional.push(columnsConditional[i]);
            }
        }
    }
    return valueConditional;
}

module.exports = (pool) => {
    router.get('/', helper.isLoggedIn, function(req, res) {
        let isAdmin = req.session.user.isadmin;
        let userId = req.session.user.userid;
        let sql = `SELECT email,firstname,lastname,role,isfulltime FROM users WHERE userid=$1`;
        pool.query(sql,[userId],function (err,response) {
            let email = response.rows[0].email;
            let firstname = response.rows[0].firstname;
            let lastname = response.rows[0].lastname;
            let role = (response.rows[0].role == null) ? '' : response.rows[0].role;
            let isFullTime = response.rows[0].isfulltime;

            res.render('profile/index',{userId,email,firstname,lastname,role,isFullTime,isAdmin});
        })
    });

    router.post('/',helper.isLoggedIn, function(req, res) {
        let boolIsFullTime = (req.body.type) ? true : false;
        if ((req.body.password == "") && (req.body.firstname == "") && (req.body.lastname == "")) {
            let sql = 'UPDATE users SET role = $1, isfulltime = $2 WHERE userid = $3';
            pool.query(sql,[req.body.position,boolIsFullTime,req.body.userid],function (err,response) {
                res.redirect('/profile');
            })
        } else {
            let fullName = (req.body.firstname + ' ' + req.body.lastname).trim();
            let setColumnsAndCounter = buildUpdateQuery([req.body.password,req.body.firstname,req.body.lastname,req.body.position,boolIsFullTime,fullName]);
            let setColumns = setColumnsAndCounter[1];
            let counter = setColumnsAndCounter[0];
            let sql = `UPDATE users SET ${setColumns} WHERE userid=$${counter}`;
            if (req.body.password == "") {
                let params = buildUpdateQueryValues([req.body.password,req.body.firstname,req.body.lastname,req.body.position,boolIsFullTime,fullName]);
                params.push(req.body.userid);
                pool.query(sql,params,function (err,response) {
                    res.redirect('/profile');
                })
            } else {
                bcrypt.hash(req.body.password,saltRounds,function (err,hash) {
                    let params = buildUpdateQueryValues([hash,req.body.firstname,req.body.lastname,req.body.position,boolIsFullTime,fullName]);
                    params.push(req.body.userid);
                    pool.query(sql,params,function (err,response) {
                        res.redirect('/profile');
                    })
                })
            }
        }

    })
    return router;
}
