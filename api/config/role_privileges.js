module.exports={

privGroups:[
{
    id:"USERS",
    name:"User Permissions"
},
{
    id:"ROLES",
    name:"Role Permissions"
},
{
    id:"CATEGORIES",
    name:"Category Permissions"
},{
    id:"AUDITLOGS",
    name:"AuditLog Permissions"
}

],
privileges:
[
        {
            key:"user_view",
            name:"User View",
            group:"USERS",
            description:"User-View Permissions"
            },
            {
            key:"user_add",
            name:"User Add",
            group:"USERS",
            description:"User-Add Permissions"
            },
            {
            key:"user_update",
            name:"User Update",
            group:"USERS",
            description:"User-Update Permissions"
            },
            {
            key:"user_delete",
            name:"User Delete",
            group:"USERS",
            description:"User-Delete Permissions"
        },
        {
            key:"role_view",
            name:"Role View",
            group:"ROLES",
            description:"Role-View Permissions"
            },
            {
            key:"role_add",
            name:"Role Add",
            group:"ROLES",
            description:"Role-Add Permissions"
            },
            {
            key:"role_update",
            name:"Role Update",
            group:"ROLES",
            description:"Role-Update Permissions"
            },
            {
            key:"role_delete",
            name:"Role Delete",
            group:"ROLES",
            description:"Role-Delete Permissions"
        },
        {
            key:"category_view",
            name:"Category View",
            group:"CATEGORIES",
            description:"Category-View Permissions"
            },
            {
            key:"category_add",
            name:"Category Add",
            group:"CATEGORIES",
            description:"Category-Add Permissions"
            },
            {
            key:"category_update",
            name:"Category Update",
            group:"CATEGORIES",
            description:"Category-Update Permissions"
            },
            {
            key:"category_delete",
            name:"Category Delete",
            group:"CATEGORIES",
            description:"Category-Delete Permissions"
           },
           {
            key:"category_export",
            name:"Category Export",
            group:"CATEGORIES",
            description:"Category-Export Permissions"


           },
        {
            key:"auditlog_view",
            name:"Auditlog View",
            group:"AUDITLOGS",
            description:"AuditLog-View Permissions"
            },
            {
            key:"auditlog_add",
            name:"Auditlog Add",
            group:"AUDITLOGS",
            description:"Auditlog-Add Permissions"
            },
            {
            key:"AuditLog_update",
            name:"Auditlog Update",
            group:"AUDITLOGS",
            description:"Auditlog-Update Permissions"
            },
            {
            key:"auditlog_delete",
            name:"Auditlog Delete",
            group:"AUDITLOGS",
            description:"Auditlog-Delete Permissions"
        }

]

}