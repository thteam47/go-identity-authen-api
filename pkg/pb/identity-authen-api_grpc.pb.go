// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.7.1
// source: identity-authen-api.proto

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// IdentityAuthenServiceClient is the client API for IdentityAuthenService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IdentityAuthenServiceClient interface {
	Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error)
	Logout(ctx context.Context, in *Request, opts ...grpc.CallOption) (*MessageResponse, error)
	PrepareLogin(ctx context.Context, in *PrepareLoginRequest, opts ...grpc.CallOption) (*PrepareLoginResponse, error)
	ForgotPassword(ctx context.Context, in *ForgotPasswordRequest, opts ...grpc.CallOption) (*MessageResponse, error)
	UpdateForgotPassword(ctx context.Context, in *UpdatePasswordRequest, opts ...grpc.CallOption) (*MessageResponse, error)
	UpdatePassword(ctx context.Context, in *UpdatePasswordRequest, opts ...grpc.CallOption) (*MessageResponse, error)
	UpdateMfa(ctx context.Context, in *UpdateMfaRequest, opts ...grpc.CallOption) (*MessageResponse, error)
	GetMfaType(ctx context.Context, in *StringRequest, opts ...grpc.CallOption) (*MfaResponse, error)
	RegisterUser(ctx context.Context, in *UserRegisterRequest, opts ...grpc.CallOption) (*RegisteResponse, error)
	RequestVerifyEmail(ctx context.Context, in *StringRequest, opts ...grpc.CallOption) (*MessageResponse, error)
	VerifyUser(ctx context.Context, in *Request, opts ...grpc.CallOption) (*MessageResponse, error)
	VerifyForgotPassword(ctx context.Context, in *Request, opts ...grpc.CallOption) (*MessageResponse, error)
}

type identityAuthenServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIdentityAuthenServiceClient(cc grpc.ClientConnInterface) IdentityAuthenServiceClient {
	return &identityAuthenServiceClient{cc}
}

func (c *identityAuthenServiceClient) Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error) {
	out := new(LoginResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/Login", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) Logout(ctx context.Context, in *Request, opts ...grpc.CallOption) (*MessageResponse, error) {
	out := new(MessageResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/Logout", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) PrepareLogin(ctx context.Context, in *PrepareLoginRequest, opts ...grpc.CallOption) (*PrepareLoginResponse, error) {
	out := new(PrepareLoginResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/PrepareLogin", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) ForgotPassword(ctx context.Context, in *ForgotPasswordRequest, opts ...grpc.CallOption) (*MessageResponse, error) {
	out := new(MessageResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/ForgotPassword", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) UpdateForgotPassword(ctx context.Context, in *UpdatePasswordRequest, opts ...grpc.CallOption) (*MessageResponse, error) {
	out := new(MessageResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/UpdateForgotPassword", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) UpdatePassword(ctx context.Context, in *UpdatePasswordRequest, opts ...grpc.CallOption) (*MessageResponse, error) {
	out := new(MessageResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/UpdatePassword", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) UpdateMfa(ctx context.Context, in *UpdateMfaRequest, opts ...grpc.CallOption) (*MessageResponse, error) {
	out := new(MessageResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/UpdateMfa", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) GetMfaType(ctx context.Context, in *StringRequest, opts ...grpc.CallOption) (*MfaResponse, error) {
	out := new(MfaResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/GetMfaType", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) RegisterUser(ctx context.Context, in *UserRegisterRequest, opts ...grpc.CallOption) (*RegisteResponse, error) {
	out := new(RegisteResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/RegisterUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) RequestVerifyEmail(ctx context.Context, in *StringRequest, opts ...grpc.CallOption) (*MessageResponse, error) {
	out := new(MessageResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/RequestVerifyEmail", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) VerifyUser(ctx context.Context, in *Request, opts ...grpc.CallOption) (*MessageResponse, error) {
	out := new(MessageResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/VerifyUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *identityAuthenServiceClient) VerifyForgotPassword(ctx context.Context, in *Request, opts ...grpc.CallOption) (*MessageResponse, error) {
	out := new(MessageResponse)
	err := c.cc.Invoke(ctx, "/identity_authen_api.IdentityAuthenService/VerifyForgotPassword", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IdentityAuthenServiceServer is the server API for IdentityAuthenService service.
// All implementations must embed UnimplementedIdentityAuthenServiceServer
// for forward compatibility
type IdentityAuthenServiceServer interface {
	Login(context.Context, *LoginRequest) (*LoginResponse, error)
	Logout(context.Context, *Request) (*MessageResponse, error)
	PrepareLogin(context.Context, *PrepareLoginRequest) (*PrepareLoginResponse, error)
	ForgotPassword(context.Context, *ForgotPasswordRequest) (*MessageResponse, error)
	UpdateForgotPassword(context.Context, *UpdatePasswordRequest) (*MessageResponse, error)
	UpdatePassword(context.Context, *UpdatePasswordRequest) (*MessageResponse, error)
	UpdateMfa(context.Context, *UpdateMfaRequest) (*MessageResponse, error)
	GetMfaType(context.Context, *StringRequest) (*MfaResponse, error)
	RegisterUser(context.Context, *UserRegisterRequest) (*RegisteResponse, error)
	RequestVerifyEmail(context.Context, *StringRequest) (*MessageResponse, error)
	VerifyUser(context.Context, *Request) (*MessageResponse, error)
	VerifyForgotPassword(context.Context, *Request) (*MessageResponse, error)
	mustEmbedUnimplementedIdentityAuthenServiceServer()
}

// UnimplementedIdentityAuthenServiceServer must be embedded to have forward compatible implementations.
type UnimplementedIdentityAuthenServiceServer struct {
}

func (UnimplementedIdentityAuthenServiceServer) Login(context.Context, *LoginRequest) (*LoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) Logout(context.Context, *Request) (*MessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Logout not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) PrepareLogin(context.Context, *PrepareLoginRequest) (*PrepareLoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PrepareLogin not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) ForgotPassword(context.Context, *ForgotPasswordRequest) (*MessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ForgotPassword not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) UpdateForgotPassword(context.Context, *UpdatePasswordRequest) (*MessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateForgotPassword not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) UpdatePassword(context.Context, *UpdatePasswordRequest) (*MessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePassword not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) UpdateMfa(context.Context, *UpdateMfaRequest) (*MessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateMfa not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) GetMfaType(context.Context, *StringRequest) (*MfaResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMfaType not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) RegisterUser(context.Context, *UserRegisterRequest) (*RegisteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterUser not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) RequestVerifyEmail(context.Context, *StringRequest) (*MessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestVerifyEmail not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) VerifyUser(context.Context, *Request) (*MessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyUser not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) VerifyForgotPassword(context.Context, *Request) (*MessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyForgotPassword not implemented")
}
func (UnimplementedIdentityAuthenServiceServer) mustEmbedUnimplementedIdentityAuthenServiceServer() {}

// UnsafeIdentityAuthenServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IdentityAuthenServiceServer will
// result in compilation errors.
type UnsafeIdentityAuthenServiceServer interface {
	mustEmbedUnimplementedIdentityAuthenServiceServer()
}

func RegisterIdentityAuthenServiceServer(s grpc.ServiceRegistrar, srv IdentityAuthenServiceServer) {
	s.RegisterService(&IdentityAuthenService_ServiceDesc, srv)
}

func _IdentityAuthenService_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/Login",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).Login(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_Logout_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).Logout(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/Logout",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).Logout(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_PrepareLogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PrepareLoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).PrepareLogin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/PrepareLogin",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).PrepareLogin(ctx, req.(*PrepareLoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_ForgotPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ForgotPasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).ForgotPassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/ForgotPassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).ForgotPassword(ctx, req.(*ForgotPasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_UpdateForgotPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdatePasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).UpdateForgotPassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/UpdateForgotPassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).UpdateForgotPassword(ctx, req.(*UpdatePasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_UpdatePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdatePasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).UpdatePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/UpdatePassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).UpdatePassword(ctx, req.(*UpdatePasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_UpdateMfa_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateMfaRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).UpdateMfa(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/UpdateMfa",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).UpdateMfa(ctx, req.(*UpdateMfaRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_GetMfaType_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StringRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).GetMfaType(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/GetMfaType",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).GetMfaType(ctx, req.(*StringRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_RegisterUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserRegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).RegisterUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/RegisterUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).RegisterUser(ctx, req.(*UserRegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_RequestVerifyEmail_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StringRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).RequestVerifyEmail(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/RequestVerifyEmail",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).RequestVerifyEmail(ctx, req.(*StringRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_VerifyUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).VerifyUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/VerifyUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).VerifyUser(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _IdentityAuthenService_VerifyForgotPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IdentityAuthenServiceServer).VerifyForgotPassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/identity_authen_api.IdentityAuthenService/VerifyForgotPassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IdentityAuthenServiceServer).VerifyForgotPassword(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

// IdentityAuthenService_ServiceDesc is the grpc.ServiceDesc for IdentityAuthenService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IdentityAuthenService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "identity_authen_api.IdentityAuthenService",
	HandlerType: (*IdentityAuthenServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Login",
			Handler:    _IdentityAuthenService_Login_Handler,
		},
		{
			MethodName: "Logout",
			Handler:    _IdentityAuthenService_Logout_Handler,
		},
		{
			MethodName: "PrepareLogin",
			Handler:    _IdentityAuthenService_PrepareLogin_Handler,
		},
		{
			MethodName: "ForgotPassword",
			Handler:    _IdentityAuthenService_ForgotPassword_Handler,
		},
		{
			MethodName: "UpdateForgotPassword",
			Handler:    _IdentityAuthenService_UpdateForgotPassword_Handler,
		},
		{
			MethodName: "UpdatePassword",
			Handler:    _IdentityAuthenService_UpdatePassword_Handler,
		},
		{
			MethodName: "UpdateMfa",
			Handler:    _IdentityAuthenService_UpdateMfa_Handler,
		},
		{
			MethodName: "GetMfaType",
			Handler:    _IdentityAuthenService_GetMfaType_Handler,
		},
		{
			MethodName: "RegisterUser",
			Handler:    _IdentityAuthenService_RegisterUser_Handler,
		},
		{
			MethodName: "RequestVerifyEmail",
			Handler:    _IdentityAuthenService_RequestVerifyEmail_Handler,
		},
		{
			MethodName: "VerifyUser",
			Handler:    _IdentityAuthenService_VerifyUser_Handler,
		},
		{
			MethodName: "VerifyForgotPassword",
			Handler:    _IdentityAuthenService_VerifyForgotPassword_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "identity-authen-api.proto",
}
