package component

import (
	grpcauth "github.com/thteam47/common/grpcutil"
	"github.com/thteam47/common/handler"
)

type ComponentFactory interface {
	Handler() *handler.Handler
	CreateAuthService() *grpcauth.AuthInterceptor
	CreateUserService() (UserService, error)
	CreateAuthenInfoRepository() (AuthenInfoRepository, error)
	CreateCustomerService() (CustomerService, error)
}
