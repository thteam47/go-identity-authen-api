package defaultcomponent

import (
	"github.com/thteam47/common-libs/confg"
	grpcauth "github.com/thteam47/common/grpcutil"
	"github.com/thteam47/common/handler"
	"github.com/thteam47/go-identity-authen-api/errutil"
	"github.com/thteam47/go-identity-authen-api/pkg/component"
)

type ComponentFactory struct {
	properties confg.Confg
	handle     *handler.Handler
}

func NewComponentFactory(properties confg.Confg, handle *handler.Handler) (*ComponentFactory, error) {
	inst := &ComponentFactory{
		properties: properties,
		handle:     handle,
	}

	return inst, nil
}

func (inst *ComponentFactory) Handler() *handler.Handler {
	return inst.handle
}

func (inst *ComponentFactory) CreateAuthService() *grpcauth.AuthInterceptor {
	authService := grpcauth.NewAuthInterceptor(inst.handle)
	return authService
}
func (inst *ComponentFactory) CreateUserService() (component.UserService, error) {
	userService, err := NewUserServiceWithConfig(inst.properties.Sub("user-service"))
	if err != nil {
		return nil, errutil.Wrapf(err, "NewUserServiceWithConfig")
	}
	return userService, nil
}
func (inst *ComponentFactory) CreateAuthenInfoRepository() (component.AuthenInfoRepository, error) {
	authenInfoRepository, err := NewAuthenInfoRepositoryWithConfig(inst.properties.Sub("authen-info-repository"))
	if err != nil {
		return nil, errutil.Wrapf(err, "NewAuthenInfoRepositoryWithConfig")
	}
	return authenInfoRepository, nil
}
func (inst *ComponentFactory) CreateCustomerService() (component.CustomerService, error) {
	customerService, err := NewCustomerServiceWithConfig(inst.properties.Sub("customer-service"))
	if err != nil {
		return nil, errutil.Wrapf(err, "NewCustomerServiceWithConfig")
	}
	return customerService, nil
}