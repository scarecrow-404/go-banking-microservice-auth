package domain

type RolePermission struct {
	rolePermission map[string][]string
}

func (r RolePermission) HasPermission(role string, resource string) bool {
	permissions := r.rolePermission[role]
	for _, permission := range permissions {
		if permission == resource {
			return true
		}
	}
	return false
}

func GetRolePermission() RolePermission {
	return RolePermission{map[string][]string{
		"admin": {"GetAllCustomers", "GetCustomer", "NewAccount", "NewTransaction"},
		"user":  {"GetCustomer", "NewTransaction"},
	}}
}