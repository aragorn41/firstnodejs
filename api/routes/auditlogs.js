var express = require('express');
const moment =require('moment');
const Response = require('../lib/Response');

const AuditLogs = require('../db/models/AuditLogs');
var router = express.Router();
const auth=require("../lib/auth")();


router.all("*",auth.authenticate(),(req,res,next)=>{
  next();
});

/* GET users listing. */
router.post("/", auth.checkRoles("auditlogs_view"), async function(req, res) {
  try {

    let body=req.body;
    let query={};
    let skip = body.skip;
    let limit = body.limit;

    if (typeof body.skip !== "number") {
      skip = 0;
  }
  if (typeof body.limit !== "number" || body.limit > 500) {
    limit = 500;
}

    if(body.begin_date && body.end_date)
    {
      query.created_at=
      {
        $gte:moment(body.begin_date),
        $lte:moment(body.end_date)
      }

    }
    else (
      query.created_at=
      {
        $gte:moment().subtract(1,"day").startOf("day"),
        $lte:moment()
      }


    )

                                          //500 500 getir /Skip kaçıncı sayfa //Sort desc: -1
   let auditLogs = await AuditLogs.find(query).sort({ created_at: -1 }).skip(skip).limit(limit);
res.json(Response.successResponse(auditLogs));

  } 
  catch (err) {
    let errorResponse=Response.errorResponse(err,req.user?.language);
    res.status(errorResponse.code).json(errorResponse);
  }
});

module.exports = router;
