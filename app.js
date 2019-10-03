var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');
var fileUpload = require('express-fileupload');
const pg = require('pg');
// const pool = new pg.Pool({
//     user: 'postgres',
//     host: '127.0.0.1',
//     database: 'PMS',
//     password: 'admin1234',
//     port:'5432'
// })
const pool = new pg.Pool({
    user: 'oeqzzrnfqhjenc',
    host: 'ec2-54-235-167-210.compute-1.amazonaws.com',
    database: 'd5kautgck30taj',
    password: 'f6115206ef0ccd3dbad94024c589abadae15dbd0d03a7a908a50fa785e376b1e',
    port:'5432'
})

var indexRouter = require('./routes/index');
var projectsRouter = require('./routes/projects');
var profileRouter = require('./routes/profile');
var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({secret: "persib1994salawasna"}));
app.set('etag', false);
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private')
  next()
});

app.use(fileUpload());
app.use('/', indexRouter(pool));
app.use('/projects', projectsRouter(pool));
app.use('/profile', profileRouter(pool));
app.use('/users', usersRouter(pool));

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
