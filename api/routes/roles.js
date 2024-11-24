var express = require('express');
var router = express.Router();

const Roles=require("../db/models/Roles");
const RolePrivileges=require("../db/models/RolePrivileges");
const Response=require("../lib/Response");
const CustomError=require("../lib/Error");
const Enum=require("../config/Enum");
const role_privileges=require("../config/role_privileges");
const config=require("../config")
const i18n=new (require("../lib/i18n"))(config.DEFAULT_LANG);

const auth=require("../lib/auth")();
router.all("*",auth.authenticate(),(req,res,next)=>{
  next();
});

router.get('/',auth.checkRoles("role_view"),async function(req,res){

  try {
    let roles=await Roles.find({});
    res.json(Response.successResponse(roles));
    
  } catch (err) {

    let errorResponse=Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
     

  }


});

router.post("/add",auth.checkRoles("role_add"),async (req,res) => {
  let body=req.body;
try {
  if (!body.role_name) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST,i18n.translate("COMMON.VALIDATION_ERROR_TITLE",req.user?.language),i18n.translate("COMMON.FIELD_MUST_BE_FILLED",req.user.language,["role_name"]));
  if(!body.permissions || !Array.isArray(body.permissions) || body.permissions.length==0) {

    throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST,"Permission alanı boş olamaz");

  }
  let role=new Roles({

    role_name: body.role_name,
    is_active:true,
    created_by:req.user?.id

  });

  await role.save();

for (let i=0;i<body.permissions.length; i++)
{
let priv=new RolePrivileges(
  {
    role_id:role._id,
    permission:body.permissions[i],
    created_by:req.user?.id

  }
);
await priv.save();

}

res.json(Response.successResponse({success:true}))
  
} catch (err) {
  let errorResponse=Response.errorResponse(err);
  res.status(errorResponse.code).json(errorResponse);
  
}

});

router.post("/update",auth.checkRoles("role_update"),async(req,res)=>{

  let body=req.body;
  try {
    if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST,i18n.translate("COMMON.VALIDATION_ERROR_TITLE",req.user?.language),i18n.translate("COMMON.FIELD_MUST_BE_FILLED",req.user.language,["_id"]));
 
    let updates={};
    if(body.role_name) updates.role_name=body.role_name;
    if(typeof body.is_active ==="boolean") updates.is_active=body.is_active;
    
    
    //#region permissions
    if(body.permissions && Array.isArray(body.permissions) && body.permissions.length>0) {



      let permissions=await RolePrivileges.find({role_id:body._id});

      let removedPermissions=permissions.filter(x=>!body.permissions.includes(x.permission));
      let newPermissions=body.permissions.filter(x=> !permissions.map(p=> p.permission).includes(x));

      if (removedPermissions.length>0)
      {
        for(let i=0;i<removedPermissions.length;i++)
        {
        await RolePrivileges.deleteOne({_id:{$in:removedPermissions[i].map(x=>x._id)}});
      }
      }

      if (newPermissions.length>0)
      {
        for (let i=0;i<newPermissions.length; i++)
          {
          let priv=new RolePrivileges(
            {
              role_id:body._id,
              permission:body.newPermissions[i],
              created_by:req.user?.id
          
            }
          );
          await priv.save();
          
          }
    
      }


      }
//#endregion

     
    await Roles.updateOne({_id:body._id},updates);
    res.json(Response.successResponse({success:true}));
    
  } catch (err) {
    let errorResponse=Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
    
  }
  
  });


  router.post("/delete",auth.checkRoles("role_delete"),async(req,res)=>{

    let body=req.body;
    try {
      if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST,i18n.translate("COMMON.VALIDATION_ERROR_TITLE",req.user?.language),i18n.translate("COMMON.FIELD_MUST_BE_FILLED",req.user.language,["_id"]));
      
      await Roles.deleteOne({ _id: body._id });
  
      res.json(Response.successResponse({success:true}));
      
    } catch (err) {
      let errorResponse=Response.errorResponse(err);
      res.status(errorResponse.code).json(errorResponse);
      
    }
    
    });
  


    router.get('/role_privileges',async function(req,res){

      res.json(role_privileges);
    
    
    });
    

module.exports = router;