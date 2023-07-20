package servergrpc

import (
	defaultcomponent "github.com/thteam47/go-identity-authen-api/pkg/component/default"
	"net"

	"github.com/thteam47/common-libs/confg"
	"github.com/thteam47/common/handler"
	"github.com/thteam47/go-identity-authen-api/errutil"
	"github.com/thteam47/go-identity-authen-api/pkg/component"
	"github.com/thteam47/go-identity-authen-api/pkg/grpcapp"
	pb "github.com/thteam47/common/api/identity-authen-api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func Run(lis net.Listener, properties confg.Confg, handler *handler.Handler) error {
	componentFactory, err := defaultcomponent.NewComponentFactory(properties.Sub("components"), handler)
	if err != nil {
		return errutil.Wrap(err, "NewComponentFactory")
	}
	componentsContainer, err := component.NewComponentsContainer(componentFactory)
	if err != nil {
		return errutil.Wrap(err, "NewComponentsContainer")
	}
	serverOptions := []grpc.ServerOption{}
	s := grpc.NewServer(serverOptions...)
	pb.RegisterIdentityAuthenServiceServer(s, grpcapp.NewIdentityAuthenService(componentsContainer))
	reflection.Register(s)
	return s.Serve(lis)
}
