var express = require('express');
var router = express.Router();
var helper = require('../helper/utils');
var path = require('path');

function convertResultConditionalToString(resultConditional) {
    let stringResultConditional = "";
    for (let i=0;i<resultConditional.length;i++) {
        if (resultConditional[i] != "") {
            stringResultConditional += resultConditional[i] + " AND ";
        }
    }
    if (stringResultConditional != "") {
        stringResultConditional = stringResultConditional.substring(0,stringResultConditional.length-5);
    }
    return stringResultConditional;
}

function stringConditional(searchFilter) {
    let resultConditional = [];
    resultConditional[0] = (searchFilter[0] == 'on') ? `projectid = $` : ``;
    resultConditional[1] = (searchFilter[1] == 'on') ? `name = $` : ``;
    resultConditional[2] = (searchFilter[2] == 'on') ? `projectid IN (SELECT projectid FROM members WHERE userid=$)` : ``;
    let counter = 1
    for (let i=0;i<resultConditional.length;i++) {
        if (searchFilter[i] == 'on') {
            if (i == 2) {
                let stringReplace = 'userid=$' + counter;
                resultConditional[i] = resultConditional[i].replace('userid=$',stringReplace);
            } else {
                resultConditional[i] += counter;
            }
            counter++;
        }
    }
    return [counter,convertResultConditionalToString(resultConditional)];
}

function stringConditionalMember(searchFilter) {
    let resultConditional = [];
    // "SELECT count(*) as total FROM (members INNER JOIN users ON members.userid = users.userid) WHERE userid=$1 AND role=$2 AND fullname=$3 AND projectid=$4"
    resultConditional[0] = (searchFilter[0]) ? `users.userid = $` : ``;
    resultConditional[1] = (searchFilter[1]) ? `users.fullname = $` : ``;
    resultConditional[2] = (searchFilter[2]) ? `members.role = $` : ``;
    let counter = 1
    for (let i=0;i<resultConditional.length;i++) {
        if (searchFilter[i]) {
            resultConditional[i] += counter;
            counter++;
        }
    }
    resultConditional.push('projectid = $' + counter);
    counter++;
    return [counter,convertResultConditionalToString(resultConditional)];
}

function stringConditionalIssue(searchFilter) {
    let resultConditional = [];
    resultConditional[0] = (searchFilter[0]) ? `issueid = $` : ``;
    resultConditional[1] = (searchFilter[1]) ? `subject = $` : ``;
    resultConditional[2] = (searchFilter[2]) ? `tracker = $` : ``;
    let counter = 1
    for (let i=0;i<resultConditional.length;i++) {
        if (searchFilter[i]) {
            resultConditional[i] += counter;
            counter++;
        }
    }
    resultConditional.push('projectid = $' + counter);
    counter++;
    return [counter,convertResultConditionalToString(resultConditional)];
}

function valueConditional(searchFilter,searchFilterValue) {
    let resultFilterValue = [];
    for (let i=0;i<searchFilterValue.length;i++) {
        if (searchFilter[i] == 'on') {
            resultFilterValue.push(searchFilterValue[i]);
        }
    }
    return resultFilterValue;
}

function convertDateToString(date) {
    let year = date.getFullYear();
    let month = date.getMonth() + 1;
    if (month.toString().length < 2) {
        month = '0' + month;
    }
    let day = date.getDate();
    if (day.toString().length < 2) {
        day = '0' + day;
    }
    return year + '-' + month + '-' + day;
}

module.exports = (pool) => {

    router.get('/', helper.isLoggedIn, function(req, res) {
        let isAdmin = req.session.user.isadmin;
        let searchFilter = [req.query.id_checkbox,req.query.name_checkbox,req.query.member_checkbox];
        let searchFilterValue = [req.query.id,req.query.name,req.query.member];

        let stringCondition = stringConditional(searchFilter)[1];
        let stringConditionValue = valueConditional(searchFilter,searchFilterValue);
        let counterStringCondition = stringConditional(searchFilter)[0];

        let sql = `SELECT count(*) as total FROM projects WHERE ${stringCondition}`;
        if (stringCondition == "") {
            sql = `SELECT count(*) as total FROM projects`;
        }
        pool.query(sql,stringConditionValue,function (err,response) {
            if (err) throw err;

            let url = req.url == '/' ? '/projects/?page=1' : '/projects' + req.url;
            let total = response.rows[0].total;
            let page = req.query.page || 1;
            let limit = 3;
            let totalPage = Math.ceil(total / limit);
            let offSet = limit * (page - 1);

            sql = 'SELECT projectoptions FROM users WHERE userid=$1';
            pool.query(sql,[req.session.user.userid],function (err,response) {
                let options = response.rows[0].projectoptions == null ? '{}' : response.rows[0].projectoptions;
                options = JSON.parse(options);

                sql = `SELECT * FROM projects WHERE ${stringCondition} ORDER by projectid LIMIT $${counterStringCondition} OFFSET $${counterStringCondition+1}`;
                if (stringCondition == "") {
                    sql = `SELECT * FROM projects ORDER by projectid LIMIT $${counterStringCondition} OFFSET $${counterStringCondition+1}`;
                }
                stringConditionValue.push(limit);
                stringConditionValue.push(offSet);
                pool.query(sql, stringConditionValue, function (err,response) {
                    if (err) throw err;
                    let arrayProjects = []
                    let arrayIDProjects = []
                    let arrayIndexIDProjects = [];
                    for (let i=0;i<response.rows.length;i++) {
                        let project = {};
                        if (options.id_column) project['id'] = response.rows[i].projectid;
                        if (options.name_column) project['name'] = response.rows[i].name;
                        if (options.members_column) project['members'] = [];
                        arrayProjects.push(project);
                        arrayIDProjects.push(response.rows[i].projectid);
                        arrayIndexIDProjects[response.rows[i].projectid] = i;
                    }

                    sql = `SELECT * FROM users`;
                    pool.query(sql, function (err,response) {
                        let users = response.rows;
                        if (options.members_column) {
                            sql = `SELECT * FROM ((members INNER JOIN projects ON members.projectid = projects.projectid) INNER JOIN users ON members.userid = users.userid) WHERE projects.projectid IN (${arrayIDProjects})`;
                            pool.query(sql, function(err,response) {
                                if (response) {
                                    for (let j=0;j<response.rows.length;j++) {
                                        let projectID = response.rows[j].projectid;
                                        let fullName = response.rows[j].fullname;
                                        arrayProjects[arrayIndexIDProjects[projectID]].members.push(fullName);
                                    }
                                }
                                res.render('projects/index',{arrayProjects,options,users,totalPage,page,url,isAdmin});
                            })
                        } else {
                            res.render('projects/index',{arrayProjects,options,users,totalPage,page,url,isAdmin});
                        }
                    })
                })
            })
        })
    });

    router.post('/option', helper.isLoggedIn, function (req,res) {
        let sql = "UPDATE users SET projectoptions=$1 WHERE userid = $2";
        pool.query(sql, [JSON.stringify(req.body),req.session.user.userid], function (err,response) {
            if (err) console.log(err);
            res.redirect('/projects');
        })
    })

    router.get('/add', helper.isLoggedIn, function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let sql = "SELECT * FROM users";
        pool.query(sql, function (err,response) {
            let users = response.rows;
            res.render('projects/add',{users,isAdmin});
        })
    });

    router.post('/add',helper.isLoggedIn, function (req,res) {
        let sql = "INSERT INTO projects(name) VALUES ($1)";
        pool.query(sql,[req.body.name],function (err,response) {
            if (err) throw err;
            sql = "SELECT * FROM projects WHERE name=$1";
            pool.query(sql,[req.body.name],function (err,response) {
                let idProject = response.rows[0].projectid;
                let arrayKeys = [];
                for (key in req.body) {
                    if (key != 'name') {
                        if (req.body[key] == 'on') {
                            arrayKeys.push(key);
                        }
                    }
                }
                if (arrayKeys.length == 0) {
                    res.redirect('/projects');
                } else {
                    sql = "INSERT INTO members(projectid,userid) VALUES ($1,$2)";
                    for (let i=0;i<arrayKeys.length;i++) {
                        pool.query(sql,[idProject,arrayKeys[i]],function(err,response) {
                            res.redirect('/projects');
                        });
                    }
                }
            })
        })
    })

    router.get('/delete/:id',helper.isLoggedIn,function (req,res) {
        let idProject = req.params.id;
        let sql = `DELETE FROM members WHERE projectid = $1`;
        pool.query(sql,[idProject],function (err,response) {
            if (err) throw err;
            sql = `DELETE FROM projects WHERE projectid = $1`;
            pool.query(sql,[idProject],function (err,response) {
                if (err) throw err;
                res.redirect('/projects');
            })
        })
    })

    router.get('/edit/:id',helper.isLoggedIn,function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let idProject = req.params.id;
        let sql = `SELECT * FROM projects WHERE projectid=$1`;
        pool.query(sql,[idProject],function (err,response) {
            if (err) throw err;
            let nameProject = response.rows[0].name;
            sql = `SELECT * FROM members WHERE projectid=$1`;
            pool.query(sql,[idProject],function (req,response) {
                let arrayMembersId = [];
                for (let i=0;i<response.rows.length;i++) {
                    arrayMembersId.push(response.rows[i].userid);
                }
                sql = `SELECT * FROM users`;
                pool.query(sql,function (req,response) {
                    let users = response.rows;
                    res.render('projects/edit',{users,arrayMembersId,nameProject,idProject,isAdmin});
                })
            })
        })
    })

    router.post('/edit',helper.isLoggedIn,function (req,res) {
        let idProject = req.body.id;
        let nameProject = req.body.name;
        let sql = "UPDATE projects SET name=$1 WHERE projectid=$2";
        pool.query(sql,[nameProject,idProject],function (err,response) {
            if (err) throw err;
            sql = `DELETE FROM members WHERE projectid=$1`;
            pool.query(sql,[idProject],function (err,response) {
                if (err) throw err;
                let arrayKeys = [];
                for (key in req.body) {
                    if ((key != 'name') && (key != 'id')) {
                        if (req.body[key] == 'on') {
                            arrayKeys.push(key);
                        }
                    }
                }
                if (arrayKeys.length == 0) {
                    res.redirect('/projects');
                } else {
                    // Build Value Params for INSERT QUERY
                    let arrayValues = [];
                    let params = [];
                    for (let i=0;i<arrayKeys.length;i++) {
                        arrayValues.push([idProject,arrayKeys[i]]);
                        params.push(idProject);
                        params.push(arrayKeys[i]);
                    }
                    // Build Conditional String For INSERT QUERY
                    let stringCondition = "";
                    let counter = 1;
                    for (let i=0;i<arrayValues.length;i++) {
                        stringCondition += `($${counter},$${counter+1})`;
                        if (i < arrayValues.length-1) {
                            stringCondition += ",";
                        }
                        counter += 2;
                    }

                    sql = `INSERT INTO members(projectid,userid) VALUES ${stringCondition}`;
                    pool.query(sql,params,function (err,response) {
                        if (err) throw err;
                        res.redirect('/projects');
                    })
                }
            })
        })
    })

    router.get('/overview/:projectid',helper.isLoggedIn,function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let idProject = req.params.projectid;
        let sql = `SELECT count(*) as total FROM issues WHERE tracker='bug' AND projectid=${idProject}`;
        pool.query(sql, function (err,response) {
            if (err) throw err;
            let bugTotal = response.rows[0].total;
            sql = `SELECT count(*) as total FROM issues WHERE tracker='bug' AND projectid=${idProject} AND status != 'closed'`;
            pool.query(sql, function (err,response) {
                if (err) throw err;
                let bugTotalOpen = response.rows[0].total;
                sql = `SELECT count(*) as total FROM issues WHERE tracker='feature' AND projectid=${idProject}`;
                pool.query(sql, function (err,response) {
                    if (err) throw err;
                    let featureTotal = response.rows[0].total;
                    sql = `SELECT count(*) as total FROM issues WHERE tracker='feature' AND projectid=${idProject} AND status != 'closed'`;
                    pool.query(sql, function (err,response) {
                        if (err) throw err;
                        let featureTotalOpen = response.rows[0].total;
                        sql = `SELECT count(*) as total FROM issues WHERE tracker='support' AND projectid=${idProject}`;
                        pool.query(sql, function (err,response) {
                            if (err) throw err;
                            let supportTotal = response.rows[0].total;
                            sql = `SELECT count(*) as total FROM issues WHERE tracker='support' AND projectid=${idProject} AND status != 'closed'`;
                            pool.query(sql, function (err,response) {
                                if (err) throw err;
                                let supportTotalOpen = response.rows[0].total;
                                sql = `SELECT users.fullname FROM (members INNER JOIN users ON members.userid = users.userid) WHERE members.projectid = ${idProject} ORDER BY users.userid`
                                pool.query(sql, function (err,response) {
                                    if (err) throw err;
                                    let listUsers = response.rows;
                                    res.render('projects/overview/index',{idProject,bugTotal,bugTotalOpen,featureTotal,featureTotalOpen,supportTotal,supportTotalOpen,listUsers,isAdmin});
                                })
                            })
                        })
                    })
                })
            })
        })
    })

    router.get('/activity/:projectid',helper.isLoggedIn,function (req,res) {
        const weekdays = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
        let isAdmin = req.session.user.isadmin;

        let idProject = req.params.projectid;
        let currentDate = new Date(Date.now());
        let lastWeekDate = new Date(Date.now());
        lastWeekDate.setDate(lastWeekDate.getDate()-6);

        // Build Empty Array Activity Object
        let startDate = new Date(Date.now());
        let endDate = new Date(Date.now());
        endDate.setDate(endDate.getDate()-6);
        let arrayActivityObject = [];
        let counter = 1;
        while (startDate >= endDate) {
            if (counter == 1) {
                arrayActivityObject['Today'] = [];
            } else {
                arrayActivityObject[weekdays[startDate.getDay()]] = [];
            }
            startDate.setDate(startDate.getDate()-1);
            counter++;
        }

        let sql = `SELECT * FROM activity WHERE ((time >= $1) AND (time <= $2)) AND projectid = $3 ORDER BY time DESC`;
        pool.query(sql, [lastWeekDate,currentDate,idProject], function (err,response) {
            if (err) throw err;
            let activities = response.rows;
            let todayDate = new Date(Date.now());
            let authorArrayPush = [];

            let counter = 0;
            for (let i=0;i<activities.length;i++) {
                let time = activities[i].time.getHours() + ':' + activities[i].time.getMinutes();
                let title = activities[i].title;
                let description = activities[i].description;
                let author = activities[i].author;
                let day = activities[i].time.getDay();
                if (todayDate.getDay() == day) {
                    day = 'Today';
                } else {
                    day = weekdays[day];
                }
                authorArrayPush.push(author);
                arrayActivityObject[day].push({
                    'Time'  :   time,
                    'Title' :   title,
                    'Description' : description,
                    'Author'  :   author
                })
                counter++;
            }

            currentDate = convertDateToString(currentDate);
            lastWeekDate = convertDateToString(lastWeekDate);

            if (authorArrayPush.length > 0) {
                sql = `SELECT userid,fullname FROM users WHERE userid IN (${authorArrayPush})`;
                pool.query(sql, function (err,response) {
                    if (err) throw err;
                    let userMap = [];
                    for (let i=0;i<response.rows.length;i++) {
                        userMap[response.rows[i].userid] = response.rows[i].fullname;
                    }
                    for (let key in arrayActivityObject) {
                        let activityObjects = arrayActivityObject[key];
                        for (let i=0;i<activityObjects.length;i++) {
                            arrayActivityObject[key][i]['Author'] = userMap[arrayActivityObject[key][i]['Author']];
                        }
                    }
                    for (let key in arrayActivityObject) {
                        arrayActivityObject[key].reverse();
                    }
                    res.render('projects/activity/index',{idProject,arrayActivityObject,currentDate,lastWeekDate,isAdmin});
                })
            } else {
                res.render('projects/activity/index',{idProject,arrayActivityObject,currentDate,lastWeekDate,isAdmin});
            }
        })
    })

    router.get('/issue/:projectid',helper.isLoggedIn,function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let idProject = req.params.projectid;
        let searchFilter = [req.query.id_checkbox,req.query.subject_checkbox,req.query.tracker_checkbox];
        let searchFilterValue = [req.query.id,req.query.subject,req.query.tracker];

        let stringConditionAndCounter = stringConditionalIssue(searchFilter);
        let stringCondition = stringConditionAndCounter[1];
        let counter = stringConditionAndCounter[0];
        let stringConditionValue = valueConditional(searchFilter,searchFilterValue);
        stringConditionValue.push(idProject);
        let sql = `SELECT count(*) as total FROM issues WHERE ${stringCondition}`;

        pool.query(sql, stringConditionValue, function (err,response) {
            if (err) throw err;

            let url = req.url == ('/issue/' + idProject) ? '/projects/issue/' + idProject + '/?page=1' : '/projects' + req.url;
            let total = response.rows[0].total;
            let page = req.query.page || 1;
            let limit = 3;
            let totalPage = Math.ceil(total / limit);
            let offSet = limit * (page - 1);

            let sql = `SELECT issueid,subject,tracker,closeddate FROM issues WHERE ${stringCondition} ORDER by issueid LIMIT $${counter} OFFSET $${counter+1}`;
            stringConditionValue.push(limit);
            stringConditionValue.push(offSet);
            pool.query(sql, stringConditionValue, function (err,response) {
                if (err) throw err;
                let arrayIssues = response.rows;

                sql = `SELECT issueoptions FROM projects WHERE projectid = $1`;
                pool.query(sql,[idProject],function (err,response) {
                    if (err) throw err;
                    let options = response.rows[0].issueoptions == null ? '{}' : response.rows[0].issueoptions;
                    options = JSON.parse(options);
                    res.render('projects/issue/index',{idProject,arrayIssues,options,totalPage,page,url,isAdmin});
                })
            })
        })
    })

    router.post('/issue/:projectid/option',helper.isLoggedIn,function (req,res) {
        let sql = "UPDATE projects SET issueoptions=$1 WHERE projectid = $2";
        pool.query(sql, [JSON.stringify(req.body),req.params.projectid], function (err,response) {
            if (err) console.log(err);
            res.redirect('/projects/issue/' + req.params.projectid);
        })
    })

    router.get('/issue/:projectid/add',helper.isLoggedIn,function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let idProject = req.params.projectid;
        let sql = `SELECT users.userid,users.fullname FROM (members INNER JOIN users ON members.userid=users.userid) WHERE members.projectid = $1`;
        pool.query(sql,[idProject],function (err,response) {
            if (err) throw err;
            let usersData = response.rows;
            res.render('projects/issue/add',{idProject,usersData,isAdmin});
        })
    })

    router.post('/issue/:projectid/add',helper.isLoggedIn,function (req,res) {
        let idProject = req.params.projectid;
        let tracker = req.body.tracker;
        let subject = req.body.subject;
        let description = req.body.description;
        let status = req.body.status;
        let priority = req.body.priority;
        let assignee = req.body.assignee || null;
        let startDate = req.body.start_date || null;
        let dueDate = req.body.due_date || null;
        let estimatedTime = req.body.estimated_time || null;
        let done = req.body.done;
        let file = req.files ? req.files.files : null;
        let fileName = req.files ? Date.now() + '_' + req.files.files.name : null;

        let sql = `INSERT INTO issues(projectid,tracker,subject,description,status,priority,assignee,startdate,duedate,estimatedtime,done,files,createddate) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())`;
        pool.query(sql,[idProject,tracker,subject,description,status,priority,assignee,startDate,dueDate,estimatedTime,done,fileName],function (err,response) {
            if (err) throw err;
            if (req.files) {
                file.mv(path.join(__dirname,`../public/images/uploaded_image/${fileName}`), function (err) {
                    if (err) throw err;
                    res.redirect('/projects/issue/' + idProject);
                })
            } else {
                res.redirect('/projects/issue/' + idProject);
            }
        })
    })

    router.get('/issue/:idproject/delete/:idissue',helper.isLoggedIn,function (req,res) {
        let idProject = req.params.idproject;
        let idIssue = req.params.idissue;
        let sql = `DELETE FROM issues WHERE projectid=${idProject} AND issueid=${idIssue}`;
        pool.query(sql,function (err,response) {
            if (err) throw err;
            res.redirect('/projects/issue/' + idProject);
        })
    })

    router.get('/issue/:idproject/edit/:idissue',helper.isLoggedIn,function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let idProject = req.params.idproject;
        let idIssue = req.params.idissue;
        let sql = `SELECT * FROM issues WHERE projectid=${idProject} AND issueid=${idIssue}`;
        pool.query(sql, function (err,response) {
            if (err) throw err;
            let issueObject = response.rows[0];
            issueObject.startdate = convertDateToString(issueObject.startdate);
            issueObject.duedate = convertDateToString(issueObject.duedate);
            sql = `SELECT users.userid,users.fullname FROM (members INNER JOIN users ON members.userid=users.userid) WHERE members.projectid = $1`;
            pool.query(sql,[idProject],function (err,response) {
                if (err) throw err;
                let usersData = response.rows;
                sql = `SELECT * FROM issues WHERE projectid=${idProject} ORDER BY issueid`;
                pool.query(sql,function (err,response) {
                    if (err) throw err;
                    let issuesData = response.rows;
                    res.render('projects/issue/edit',{idProject,idIssue,usersData,issueObject,issuesData,isAdmin});
                })
            })
        })
    })

    router.post('/issue/:idproject/edit/:idissue',helper.isLoggedIn,function (req,res) {
        let idProject = req.params.idproject;
        let idIssue = req.params.idissue;
        let tracker = req.body.tracker;
        let subject = req.body.subject;
        let description = req.body.description;
        let status = req.body.status;
        let priority = req.body.priority;
        let assignee = req.body.assignee || null;
        let startDate = req.body.start_date || null;
        let dueDate = req.body.due_date || null;
        let estimatedTime = req.body.estimated_time || null;
        let done = req.body.done;
        let file = req.files ? req.files.files : null;
        let fileName = req.files ? Date.now() + '_' + req.files.files.name : null;
        let spentTime = req.body.spent_time || null;
        let targetVersion = req.body.target_version;
        let author = req.body.author || null;
        let parentTask = req.body.parent_task || null;

        let sql;
        if (req.files) {
            sql = `UPDATE issues SET tracker=$1,subject=$2,description=$3,status=$4,priority=$5,assignee=$6,startdate=$7,duedate=$8,estimatedtime=$9,done=$10,files=$11,spenttime=$12,targetversion=$13,author=$14,updateddate=now(),parenttask=$15 WHERE projectid=${idProject} AND issueid=${idIssue}`;
            pool.query(sql,[tracker,subject,description,status,priority,assignee,startDate,dueDate,estimatedTime,done,fileName,spentTime,targetVersion,author,parentTask],function (err,response) {
                if (err) throw err;
                file.mv(path.join(__dirname,`../public/images/uploaded_image/${fileName}`), function (err) {
                    if (err) throw err;
                    if (status == 'closed') {
                        sql = `UPDATE issues SET closeddate = now() WHERE projectid=${idProject} AND issueid=${idIssue}`;
                        pool.query(sql,function (err,response) {
                            if (err) throw err;
                            sql = `INSERT INTO activity(time,title,description,author,projectid) VALUES ($1,$2,$3,$4,$5)`;
                            let time = new Date(Date.now());
                            let title = subject + ' #' + idIssue + ' (' + status + ')';
                            let description = done;
                            let author = req.session.user.userid;
                            pool.query(sql, [time,title,description,author,idProject], function (err,response) {
                                if (err) throw err;
                                res.redirect('/projects/issue/' + idProject);
                            })
                        })
                    } else {
                        sql = `INSERT INTO activity(time,title,description,author,projectid) VALUES ($1,$2,$3,$4,$5)`;
                        let time = new Date(Date.now());
                        let title = subject + ' #' + idIssue + ' (' + status + ')';
                        let description = done;
                        let author = req.session.user.userid;
                        pool.query(sql, [time,title,description,author,idProject], function (err,response) {
                            if (err) throw err;
                            res.redirect('/projects/issue/' + idProject);
                        })
                    }
                })
            })
        } else {
            sql = `UPDATE issues SET tracker=$1,subject=$2,description=$3,status=$4,priority=$5,assignee=$6,startdate=$7,duedate=$8,estimatedtime=$9,done=$10,spenttime=$11,targetversion=$12,author=$13,updateddate=now(),parenttask=$14 WHERE projectid=${idProject} AND issueid=${idIssue}`
            pool.query(sql,[tracker,subject,description,status,priority,assignee,startDate,dueDate,estimatedTime,done,spentTime,targetVersion,author,parentTask], function (err, response) {
                if (err) throw err;
                if (status == 'closed') {
                    sql = `UPDATE issues SET closeddate = now() WHERE projectid=${idProject} AND issueid=${idIssue}`;
                    pool.query(sql,function (err,response) {
                        if (err) throw err;
                        sql = `INSERT INTO activity(time,title,description,author,projectid) VALUES ($1,$2,$3,$4,$5)`;
                        let time = new Date(Date.now());
                        let title = subject + ' #' + idIssue + ' (' + status + ')';
                        let description = done;
                        let author = req.session.user.userid;
                        pool.query(sql, [time,title,description,author,idProject], function (err,response) {
                            if (err) throw err;
                            res.redirect('/projects/issue/' + idProject);
                        })
                    })
                } else {
                    sql = `INSERT INTO activity(time,title,description,author,projectid) VALUES ($1,$2,$3,$4,$5)`;
                    let time = new Date(Date.now());
                    let title = subject + ' #' + idIssue + ' (' + status + ')';
                    let description = done;
                    let author = req.session.user.userid;
                    pool.query(sql, [time,title,description,author,idProject], function (err,response) {
                        if (err) throw err;
                        res.redirect('/projects/issue/' + idProject);
                    })
                }
            })
        }
    })

    router.get('/member/:projectid',helper.isLoggedIn,function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let idProject = req.params.projectid;
        let searchFilter = [req.query.id_checkbox,req.query.name_checkbox,req.query.position_checkbox];
        let searchFilterValue = [req.query.id,req.query.name,req.query.position];

        let stringConditionAndCounter = stringConditionalMember(searchFilter);
        let stringCondition = stringConditionAndCounter[1];
        let counter = stringConditionAndCounter[0];
        let stringConditionValue = valueConditional(searchFilter,searchFilterValue);
        stringConditionValue.push(idProject);
        let sql = `SELECT count(*) as total FROM (members INNER JOIN users ON members.userid = users.userid) WHERE ${stringCondition}`;

        pool.query(sql, stringConditionValue, function (err,response) {
            if (err) throw err;

            let url = req.url == ('/member/' + idProject) ? '/projects/member/' + idProject + '/?page=1' : '/projects' + req.url;
            let total = response.rows[0].total;
            let page = req.query.page || 1;
            let limit = 3;
            let totalPage = Math.ceil(total / limit);
            let offSet = limit * (page - 1);

            let sql = `SELECT members.role,users.fullname,users.userid FROM (members INNER JOIN users ON members.userid = users.userid) WHERE ${stringCondition} ORDER BY users.userid LIMIT $${counter} OFFSET $${counter+1}`;
            stringConditionValue.push(limit);
            stringConditionValue.push(offSet);
            pool.query(sql, stringConditionValue, function (err,response) {
                if (err) throw err;
                let arrayMembers = [];
                for (let i=0;i<response.rows.length;i++) {
                    arrayMembers.push({
                        id    :   response.rows[i].userid,
                        name  :   response.rows[i].fullname,
                        role  :   response.rows[i].role
                    })
                }

                sql = `SELECT projectoptions FROM projects WHERE projectid = $1`;
                pool.query(sql, [idProject], function (err,response) {
                    if (err) throw err;
                    let options = response.rows[0].projectoptions == null ? '{}' : response.rows[0].projectoptions;
                    options = JSON.parse(options);
                    res.render('projects/member/index',{idProject,arrayMembers,options,totalPage,page,url,isAdmin});
                })
            })
        })
    })

    router.post('/member/:projectid/option',helper.isLoggedIn,function (req,res) {
        let sql = "UPDATE projects SET projectoptions=$1 WHERE projectid = $2";
        pool.query(sql, [JSON.stringify(req.body),req.params.projectid], function (err,response) {
            if (err) console.log(err);
            res.redirect('/projects/member/' + req.params.projectid);
        })
    })

    router.get('/member/:projectid/edit/:userid',helper.isLoggedIn,function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let idProject = req.params.projectid;
        let idUser = req.params.userid;
        let sql = `SELECT fullname FROM users WHERE userid=$1`;
        pool.query(sql,[idUser],function (err,response) {
            if (err) throw err;
            let fullname = response.rows[0].fullname;
            sql = `SELECT role FROM members WHERE projectid=$1 AND userid=$2`;
            pool.query(sql,[idProject,idUser],function (err,response) {
                if (err) throw err;
                let role = response.rows[0].role;
                res.render('projects/member/edit',{idProject,idUser,fullname,role,isAdmin});
            })
        })
    })

    router.post('/member/:projectid/edit/:userid',helper.isLoggedIn,function (req,res) {
        let idProject = req.params.projectid;
        let idUser = req.params.userid;
        let sql = 'UPDATE members SET role=$1 WHERE projectid=$2 AND userid=$3';
        pool.query(sql,[req.body.position,idProject,idUser],function (err,response) {
            if (err) throw err;
            res.redirect('/projects/member/' + idProject);
        })
    })

    router.get('/member/:projectid/add',helper.isLoggedIn,function (req,res) {
        let isAdmin = req.session.user.isadmin;
        let idProject = req.params.projectid;
        let sql = `SELECT userid,fullname FROM users;`
        pool.query(sql, function (err,response) {
            if (err) throw err;
            let usersData = response.rows;
            res.render('projects/member/add',{idProject,usersData,isAdmin});
        })
    })

    router.post('/member/:projectid/add',helper.isLoggedIn,function (req,res) {
        let idProject = req.params.projectid;
        let sql = `SELECT count(*) as total FROM members WHERE projectid=$1 AND userid=$2`;
        pool.query(sql,[idProject,req.body.name],function (err,response) {
            if (err) throw err;
            if (response.rows[0].total > 0) {
                res.redirect('/projects/member/'+idProject);
            } else {
                sql = `INSERT INTO members(userid,projectid,role,"isFullTime") VALUES ($1,$2,$3,$4)`;
                pool.query(sql,[req.body.name,idProject,req.body.position,(req.body.isfulltime ? true : false)],function (err,response) {
                    if (err) throw err;
                    res.redirect('/projects/member/'+idProject);
                })
            }
        })
    })

    router.get('/member/:projectid/delete/:userid',helper.isLoggedIn,function (req,res) {
        let idProject = req.params.projectid;
        let idUser = req.params.userid;
        let sql = 'DELETE FROM members WHERE userid=$1 and projectid=$2';
        pool.query(sql,[idUser,idProject],function (err,response) {
            if (err) throw err;
            res.redirect('/projects/member/' + idProject);
        })
    })

    return router;
}
