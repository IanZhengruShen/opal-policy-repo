# Role-based Access Control (RBAC) for Agentic BI
# ------------------------------------------------
#
# This policy works with the Agentic BI backend's data structure.
#
# Backend sends:
# {
#   "input": {
#     "user": {
#       "id": "uuid",
#       "company_id": "uuid",
#       "role": "analyst"
#     },
#     "action": "read",
#     "resource": {
#       "type": "database",
#       "data": {"database_name": "chinook"}
#     }
#   }
# }
#
# Policy data structure:
# {
#   "role_permissions": {
#     "analyst": [
#       {"action": "read", "type": "chinook"},
#       {"action": "read", "type": "sakila"}
#     ]
#   }
# }

package app.rbac

import future.keywords.if
import future.keywords.in

# By default, deny requests
default allow = false

# Allow admins to do anything
allow if {
    input.user.role == "admin"
}

# Allow the action if the user's role is granted permission for the specific database
allow if {
    # Only apply to database resources
    input.resource.type == "database"

    # Get the user's role from input
    user_role := input.user.role

    # Get the database name from the nested resource data
    database_name := input.resource.data.database_name

    # Look up permissions for this role
    role_permissions := data.role_permissions[user_role]

    # Check if any permission matches
    some permission in role_permissions
    permission.action == input.action
    permission.type == database_name
}

# Optional: Helper rule to check if user is admin
user_is_admin if {
    input.user.role == "admin"
}

# Optional: Helper rule to get user's accessible databases
user_accessible_databases[database] if {
    user_role := input.user.role
    role_permissions := data.role_permissions[user_role]
    some permission in role_permissions
    permission.action == "read"
    database := permission.type
}
