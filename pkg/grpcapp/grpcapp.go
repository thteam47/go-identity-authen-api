package grpcapp

import (
	"context"
	"fmt"
	"strings"
	"time"

	pb "github.com/thteam47/common/api/identity-authen-api"
	"github.com/thteam47/common/entity"
	grpcauth "github.com/thteam47/common/grpcutil"
	"github.com/thteam47/go-identity-authen-api/errutil"
	"github.com/thteam47/go-identity-authen-api/pkg/component"
	"github.com/thteam47/go-identity-authen-api/pkg/models"
	"github.com/thteam47/go-identity-authen-api/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type IdentityAuthenService struct {
	pb.IdentityAuthenServiceServer
	componentsContainer *component.ComponentsContainer
}

func NewIdentityAuthenService(componentsContainer *component.ComponentsContainer) *IdentityAuthenService {
	return &IdentityAuthenService{
		componentsContainer: componentsContainer,
	}
}

func makeUser(item *entity.User) (*pb.User, error) {
	if item == nil {
		return nil, nil
	}
	user := &pb.User{}
	err := util.ToMessage(item, user)
	if err != nil {
		return nil, errutil.Wrap(err, "ToMessage")
	}
	return user, nil
}

func (inst *IdentityAuthenService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	loginName := strings.TrimSpace(strings.ToLower(req.Username))
	loginType := strings.TrimSpace(req.Type)
	password := strings.TrimSpace(req.Password)
	requestId := strings.TrimSpace(req.RequestId)
	typeMfa := strings.TrimSpace(req.TypeMfa)
	userType := strings.TrimSpace(req.UserType)
	domain := strings.TrimSpace(req.Domain)
	if loginType == "UsernamePassword" && (loginName == "" || password == "") {
		return &pb.LoginResponse{
			Token:     "",
			ErrorCode: 400,
			Message:   "Username or password incorrect",
		}, nil
	}
	userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "@any", "@any", &grpcauth.AuthenOption{
		AuthenticationDoneRequiredDisabled: true,
	})
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}
	token, _, errorCode, message, err := inst.componentsContainer.Login(userContext, ctx, req.Ctx.AccessToken, req.Ctx.DomainId, loginType, loginName, password, req.Otp, requestId, typeMfa, userType, domain)
	if err != nil {
		return nil, errutil.Wrapf(err, "ComponentsContainer.Login")
	}
	return &pb.LoginResponse{
		Token:     token,
		ErrorCode: int32(errorCode),
		Message:   message,
	}, nil
}

func (inst *IdentityAuthenService) PrepareLogin(ctx context.Context, req *pb.PrepareLoginRequest) (*pb.PrepareLoginResponse, error) {
	userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "@any", "@any", &grpcauth.AuthenOption{
		AuthenticationDoneRequiredDisabled: false,
	})
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}

	token, requestId, secret, url, message, availbableMfas, typeMfa, err := inst.componentsContainer.PrepareLogin(userContext)
	if err != nil {
		return nil, errutil.Wrapf(err, "ComponentsContainer.PrepareLogin")
	}

	return &pb.PrepareLoginResponse{
		Token:         token,
		Message:       message,
		RequestId:     requestId,
		AvailableMfas: availbableMfas,
		TypeMfa:       typeMfa,
		Secret:        secret,
		Url:           url,
	}, nil
}

func (inst *IdentityAuthenService) UpdatePassword(ctx context.Context, req *pb.UpdatePasswordRequest) (*pb.MessageResponse, error) {
	userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "identity-authen-api:authen-info", "update", &grpcauth.AuthenOption{})
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}

	userId := strings.TrimSpace(req.UserId)
	password := strings.TrimSpace(req.Password)
	hashPassword, err := util.HashPassword(password)
	if err != nil {
		return nil, errutil.Wrapf(err, "util.HashPassword")
	}
	err = inst.componentsContainer.AuthenInfoRepository().UpdateOneByUserId(userContext, userId, map[string]interface{}{
		"HashPassword": hashPassword,
	})
	if err != nil {
		return nil, errutil.Wrapf(err, "authenInfoRepository.UpdateOneByAttr(")
	}
	return &pb.MessageResponse{
		Ok:      true,
		Message: "Update passord successful",
	}, nil

}

func (inst *IdentityAuthenService) Logout(ctx context.Context, req *pb.Request) (*pb.MessageResponse, error) {
	userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "@any", "@any", &grpcauth.AuthenOption{})
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}
	err = inst.componentsContainer.Logout(userContext)
	if err != nil {
		return nil, errutil.Wrapf(err, "ComponentsContainer.Logout")
	}
	return &pb.MessageResponse{}, nil
}

func (inst *IdentityAuthenService) ForgotPassword(ctx context.Context, req *pb.ForgotPasswordRequest) (*pb.MessageResponse, error) {
	//loginName := strings.TrimSpace(strings.ToLower(req.Data))
	//message, err := inst.componentsContainer.AuthenInfoRepository().ForgotPassword(nil, loginName)
	//if err != nil {
	//	return nil, errutil.Wrapf(err, "authenInfoRepository.ForgotPassword")
	//}
	return &pb.MessageResponse{
		Message: "message",
		Ok:      true,
	}, nil
}

func (inst *IdentityAuthenService) UpdateForgotPassword(ctx context.Context, req *pb.UpdatePasswordRequest) (*pb.MessageResponse, error) {
	//userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "@any", "@any", &grpcauth.AuthenOption{})
	//if err != nil {
	//	return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	//}
	//password := strings.TrimSpace(req.Password)
	//_, err = inst.UpdatePassword(ctx, &pb.UpdatePasswordRequest{
	//	Ctx:      req.Ctx,
	//	UserId:   userContext.GetUserId(),
	//	Password: password,
	//})
	//if err != nil {
	//	return nil, errutil.Wrapf(err, "inst.UpdatePassword")
	//}
	//fmt.Println(userContext.GetAccessToken())
	//
	//err = inst.handler.RedisRepository.SetValueCache(fmt.Sprintf("invalid-token-%s", userContext.GetAccessToken()), userContext.GetAccessToken(), 5*time.Minute)
	//if err != nil {
	//	return nil, errutil.Wrapf(err, "RedisRepository.SetValueCache")
	//}
	return &pb.MessageResponse{
		Message: "Update Password Successfull",
		Ok:      true,
	}, nil
}

func (inst *IdentityAuthenService) RegisterUser(ctx context.Context, req *pb.UserRegisterRequest) (*pb.RegisteResponse, error) {
	userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "@any", "@any", &grpcauth.AuthenOption{})
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}
	username := strings.TrimSpace(strings.ToLower(req.Username))
	fullName := strings.TrimSpace(strings.ToLower(req.FullName))

	tokenInfo := userContext.Get("TokenInfo").(*entity.TokenInfo)
	if tokenInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "Unauthenticated")
	}
	userInfo := &entity.User{}
	if !tokenInfo.Get("UserInfo", userInfo) {
		return nil, status.Errorf(codes.Unauthenticated, "Unauthenticated")
	}
	if tokenInfo == nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}
	user, err := inst.componentsContainer.UserService().FindByEmail(userContext, userInfo.Email)
	if err != nil {
		return nil, errutil.Wrapf(err, "UserService.FindByEmail")
	}
	if user != nil {
		return &pb.RegisteResponse{
			Message:   "Account has been register. Please register with other email",
			ErrorCode: int32(1),
		}, nil
	}
	userData := &entity.User{
		DomainId: "default",
		FullName: fullName,
		Email:    userInfo.Email,
		Username: username,
		Roles:    []string{"member"},
		Status:   "active",
		UserType: "customer",
	}

	user, err = inst.componentsContainer.UserService().Create(userContext, userData)
	if err != nil {
		return nil, errutil.Wrapf(err, "UserService.Create")
	}

	hashPassword, err := util.HashPassword(req.Password)
	if err != nil {
		return nil, errutil.Wrapf(err, "util.HashPassword")
	}
	_, err = inst.componentsContainer.AuthenInfoRepository().Create(userContext, &models.AuthenInfo{
		UserId:       user.UserId,
		HashPassword: hashPassword,
	})
	if err != nil {
		return nil, errutil.Wrapf(err, "AuthenInfoRepository.Create")
	}

	token, _, errorCode, message, err := inst.componentsContainer.Login(entity.NewUserContext("default"), ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "UsernamePassword", userInfo.Email, req.Password, 0, "", "", "", "")
	if err != nil {
		return nil, errutil.Wrapf(err, "ComponentsContainer.Login")
	}
	// apiUserInfo, err := makeUser(userInfo)
	// if err != nil {
	// 	return nil, errutil.Wrapf(err, "makeUser.userInfo")
	// }
	return &pb.RegisteResponse{
		Token:     token,
		ErrorCode: int32(errorCode),
		Message:   message,
	}, nil
}

func (inst *IdentityAuthenService) RequestVerifyEmail(ctx context.Context, req *pb.StringRequest) (*pb.MessageResponse, error) {
	userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "@any", "@any", &grpcauth.AuthenOption{})
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}
	email := strings.TrimSpace(strings.ToLower(req.Value))
	user, err := inst.componentsContainer.UserService().FindByEmail(userContext, email)
	if err != nil {
		return nil, errutil.Wrapf(err, "UserService.FindByEmail")
	}
	if user != nil {
		return &pb.MessageResponse{
			Message: "Account has been exist. Please register with other email",
			Ok:      false,
		}, nil
	}
	tokenInfo := &entity.TokenInfo{
		AuthenticationDone: false,
		DomainId:           "default",
		Exp:                int64(time.Now().Add(30 * time.Minute).Unix()),
	}
	tokenInfo.Set("UserInfo", entity.User{
		Email: email,
	})
	token, err := inst.componentsContainer.AuthService().GenerateToken(tokenInfo)
	if err != nil {
		return nil, errutil.Wrapf(err, "AuthService.GenerateToken")
	}
	dataMail, err := util.ParseTemplate("./util/template.html", map[string]string{
		"message":    "Click the link to register account.",
		"email":      email,
		"title":      "Register Account",
		"buttonText": "Register Now",
		"link":       fmt.Sprintf("http://localhost:4200/register/%s", token),
	})
	if err != nil {
		return nil, errutil.Wrapf(err, "util.ParseTemplate")
	}
	err = util.SendMail([]string{email}, dataMail)
	if err != nil {
		return nil, errutil.Wrapf(err, "util.SendMail")
	}
	return &pb.MessageResponse{
		Message: "Please check link your email",
		Ok:      true,
	}, nil
}

//func (inst *AuthenInfoRepository) RegisterUser(userContext entity.UserContext, username string, fullName string, email string) (string, error) {
//	userData := &v1.User{
//		FullName:   fullName,
//		Email:      email,
//		Username:   username,
//		Role:       "member",
//		CreateTime: int32(time.Now().Unix()),
//		Status:     "pending",
//	}
//	userItem, err := inst.userService.Create(userContext, userData)
//	if err != nil {
//		return "", errutil.Wrapf(err, "userService.FindByLoginName")
//	}
//	if userItem == nil {
//		return "", errutil.NewWithMessage("Username or password incorrect")
//	}
//	tokenInfo := &models.TokenInfo{
//		AuthenticationDone: true,
//		UserId:             userItem.UserId,
//		Exp:                int32(time.Now().Add(5 * time.Minute).Unix()),
//	}
//	token, err := inst.jwtRepository.Generate(tokenInfo)
//	if err != nil {
//		return "", errutil.Wrapf(err, "jwtRepository.Generate")
//	}
//	dataMail, err := util.ParseTemplate("../util/template.html", map[string]string{
//		"message":    "Click the link to verify account.",
//		"username":   fullName,
//		"title":      "Verify Account",
//		"buttonText": "Verify Now",
//		"link":       fmt.Sprintf("http://localhost:4200/verify-account/%s", token),
//	})
//	if err != nil {
//		return "", errutil.Wrapf(err, "util.ParseTemplate")
//	}
//	err = util.SendMail([]string{userItem.Email}, dataMail)
//	if err != nil {
//		return "", errutil.Wrapf(err, "util.SendMail")
//	}
//	return fmt.Sprintf("Click the link in your email %s to verify your account", userData.Email), nil
//}

func (inst *IdentityAuthenService) VerifyUser(ctx context.Context, req *pb.Request) (*pb.MessageResponse, error) {
	//userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "@any", "@any", &grpcauth.AuthenOption{})
	//if err != nil {
	//	return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	//}
	//err = inst.userService.VerifyUser(userContext, "")
	//if err != nil {
	//	return nil, errutil.Wrapf(err, "authenInfoRepository.RegisterUser")
	//}

	return &pb.MessageResponse{
		Message: "Account has been actived",
		Ok:      true,
	}, nil
}

func (inst *IdentityAuthenService) VerifyForgotPassword(ctx context.Context, req *pb.Request) (*pb.MessageResponse, error) {
	//userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "@any", "@any", &grpcauth.AuthenOption{})
	//if err != nil {
	//	return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	//}
	//if userContext == nil {
	//	return &pb.MessageResponse{
	//		Ok: false,
	//	}, nil
	//}
	return &pb.MessageResponse{
		Ok: true,
	}, nil
}
