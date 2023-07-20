package component

import (
	"github.com/thteam47/common/entity"
	"github.com/thteam47/go-identity-authen-api/pkg/models"
)

type CustomerService interface {
	FindByDomain(userContext entity.UserContext, name string) (*models.Tenant, error)
}
