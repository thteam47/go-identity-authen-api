package component

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/thteam47/common-libs/strutil"

	"github.com/thteam47/common/entity"
	"github.com/thteam47/common/handler"
	"github.com/thteam47/common/pkg/entityutil"

	"github.com/pquerna/otp/totp"
	uuid "github.com/satori/go.uuid"
	grpcauth "github.com/thteam47/common/grpcutil"
	"github.com/thteam47/go-identity-authen-api/errutil"
	"github.com/thteam47/go-identity-authen-api/pkg/models"
	"github.com/thteam47/go-identity-authen-api/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ComponentsContainer struct {
	userService          UserService
	authenInfoRepository AuthenInfoRepository
	authService          *grpcauth.AuthInterceptor
	handler              *handler.Handler
	customerService      CustomerService
}

func NewComponentsContainer(componentFactory ComponentFactory) (*ComponentsContainer, error) {
	inst := &ComponentsContainer{}

	var err error
	inst.authService = componentFactory.CreateAuthService()
	inst.authenInfoRepository, err = componentFactory.CreateAuthenInfoRepository()
	inst.handler = componentFactory.Handler()
	if err != nil {
		return nil, errutil.Wrap(err, "CreateAuthenInfoRepository")
	}
	inst.userService, err = componentFactory.CreateUserService()
	if err != nil {
		return nil, errutil.Wrap(err, "CreateUserService")
	}
	inst.customerService, err = componentFactory.CreateCustomerService()
	if err != nil {
		return nil, errutil.Wrap(err, "CreateCustomerService")
	}
	return inst, nil
}

func (inst *ComponentsContainer) AuthService() *grpcauth.AuthInterceptor {
	return inst.authService
}

func (inst *ComponentsContainer) UserService() UserService {
	return inst.userService
}

func (inst *ComponentsContainer) AuthenInfoRepository() AuthenInfoRepository {
	return inst.authenInfoRepository
}

func (inst *ComponentsContainer) CustomerService() CustomerService {
	return inst.customerService
}

// func getUser(item *v1Identity.User) (*models.User, error) {
// 	if item == nil {
// 		return nil, nil
// 	}
// 	user := &models.User{}
// 	err := util.FromMessage(item, user)
// 	if err != nil {
// 		return nil, errutil.Wrap(err, "FromMessage")
// 	}
// 	return user, nil
// }

var errorCodeBadRequest = 400

func (inst *ComponentsContainer) Login(userContext entity.UserContext, ctx context.Context, accessToken string, domainId string, loginType string, username string, password string, otp int32, requestId string, typeMfa string, userType string, domain string) (string, *entity.User, int, string, error) {
	tokenInfo := &entity.TokenInfo{}
	var user *entity.User
	if loginType == "UsernamePassword" {
		userItem, err := inst.userService.FindByLoginName(userContext, username)
		if err != nil {
			return "", nil, 0, "", errutil.Wrapf(err, "userService.FindByLoginName")
		}
		if userItem == nil {
			return "", nil, errorCodeBadRequest, "Username or password incorrect", nil
		}
		if userItem.Status == "pending" {
			return "", nil, errorCodeBadRequest, "Account is not activated", nil
		}
		if userItem.Status == "verified" {
			return "", nil, errorCodeBadRequest, "Account is not approved", nil
		}
		authenInfo, err := inst.authenInfoRepository.GetByUserId(userContext, userItem.UserId)
		if err != nil {
			return "", nil, 0, "", errutil.Wrapf(err, "authenInfoRepository.GetOneByAttr")
		}
		if authenInfo == nil {
			return "", nil, 0, "", nil
		}

		isComparePassword := util.CompareHashPassword(authenInfo.HashPassword, password)

		if !isComparePassword {
			return "", nil, errorCodeBadRequest, "Username or password incorrect", nil
		}
		if len(authenInfo.Mfas) == 0 {
			tokenInfo.AuthenticationDone = true
		} else {
			enabledMfa := false
			for _, item := range authenInfo.Mfas {
				if item.Enabled {
					enabledMfa = true
				}
			}
			if !enabledMfa {
				tokenInfo.AuthenticationDone = true
			}
		}
		user = userItem
	} else if loginType == "AccessToken" {
		userContext, err := inst.AuthService().Authentication(ctx, accessToken, domainId, "@any", "@any", &grpcauth.AuthenOption{})
		if err != nil {
			return "", nil, errorCodeBadRequest, "", status.Errorf(codes.PermissionDenied, errutil.Message(err))
		}
		tokenInfo = userContext.Get("TokenInfo").(*entity.TokenInfo)
		userId, err := entityutil.GetUserId(userContext)
		if err != nil {
			return "", nil, errorCodeBadRequest, "", status.Errorf(codes.Internal, errutil.Message(err))
		}
		requestIdCache := ""
		err = inst.handler.RedisRepository.GetValueCache(fmt.Sprintf("request-id-%s", userId), &requestIdCache)
		if err != nil {
			return "", nil, errorCodeBadRequest, "Request Id expired. Please login again", nil
		}
		if requestId == "" {
			return "", nil, errorCodeBadRequest, "Request Id Not Found. Please login again", nil
		}
		if strings.TrimSpace(requestId) != requestIdCache {
			return "", nil, errorCodeBadRequest, "Request Id expired. Please login again", nil
		}
		verifyMfa, err := inst.verifyMfa(userContext, userId, typeMfa, otp)
		if err != nil {
			return "", nil, errorCodeBadRequest, "inst.verifyMfa", nil
		}
		err = inst.handler.RedisRepository.RemoveValueCache(fmt.Sprintf("request-id-%s", userId))
		if err != nil {
			return "", nil, errorCodeBadRequest, "Request Id expired. Please login again", nil
		}
		if typeMfa == "EmailOtp" {
			err = inst.handler.RedisRepository.RemoveValueCache(fmt.Sprintf("email-otp-%s", userId))
			if err != nil {
				return "", nil, errorCodeBadRequest, "Request Id expired. Please login again", nil
			}
		}
		if !verifyMfa {
			return "", nil, errorCodeBadRequest, "Invalid Otp", nil
		}
		tokenInfo.AuthenticationDone = true
	} else {
		return "", nil, errorCodeBadRequest, "Login type unavailable", nil
	}

	if user != nil {
		tokenInfo.PermissionAll = user.PermissionAll
		for _, key := range user.Permissions {
			permission := entity.Permission{
				Privilege: key.Privilege,
				Actions:   key.Actions,
			}
			tokenInfo.Permissions = append(tokenInfo.Permissions, permission)
		}
		if strutil.ArrayContains(user.Roles, "admin") {
			tokenInfo.PermissionAll = true
		}
		tokenInfo.Roles = user.Roles

		if userType == "customer" {
			if user.UserType == "customer" {
				tokenInfo.Subject = fmt.Sprintf("%s:%s", "customer", user.UserId)
				tokenInfo.DomainId = domainId
			} else {
				return "", nil, errorCodeBadRequest, "Permission denied", nil
			}
		} else {
			tokenInfo.Subject = fmt.Sprintf("%s:%s", "user", user.UserId)
			user.DomainId = userContext.DomainId()
			tokenInfo.DomainId = domainId
			if domain != "" {
				tenant, err := inst.CustomerService().FindByDomain(entity.NewUserContext("default"), domain)
				if err != nil {
					return "", nil, 0, "", errutil.Wrapf(err, "CustomerService.FindByDomain")
				}
				if tenant == nil {
					return "", nil, errorCodeBadRequest, "Domain not found", nil
				}
				if tenant.CustomerId != user.UserId {
					return "", nil, errorCodeBadRequest, "Permission denied", nil
				}
				if user.UserType == "customer" {
					user.Roles = []string{"admin"}
					tokenInfo.Roles = []string{"admin"}
					tokenInfo.PermissionAll = true
				}
				tokenInfo.DomainId = tenant.TenantId
				user.DomainId = tenant.TenantId
			}
		}

		tokenInfo.Set("UserInfo", user)
	}
	tokenInfo.Exp = time.Now().Add(inst.handler.Exp).Unix()
	token, err := inst.AuthService().GenerateToken(tokenInfo)
	if err != nil {
		return "", nil, errorCodeBadRequest, "jwtRepository.Generate", nil
	}
	return token, nil, 0, "", nil
}

func (inst *ComponentsContainer) PrepareLogin(userContext entity.UserContext) (string, string, string, string, string, []string, string, error) {
	if entityutil.AuthenticationDone(userContext) {
		return userContext.AccessToken(), "", "", "", "", nil, "", nil
	}
	userId, err := entityutil.GetUserId(userContext)
	if err != nil {
		return "", "", "", "", "", nil, "", errutil.Wrapf(err, "entityutil.GetUserId")
	}
	authenInfo, err := inst.AuthenInfoRepository().GetByUserId(userContext, userId)
	if err != nil {
		return "", "", "", "", "", nil, "", errutil.Wrapf(err, "AuthenInfoRepository.GetByUserId")
	}
	if authenInfo == nil {
		return userContext.AccessToken(), "", "", "", "", nil, "", nil
	}

	requestId := uuid.NewV4().String()

	err = inst.handler.RedisRepository.SetValueCache(fmt.Sprintf("request-id-%s", userId), requestId, inst.handler.TimeRequestId)
	if err != nil {
		return "", "", "", "", "", nil, "", errutil.Wrapf(err, "RedisRepository.SetValueCache")
	}
	availbableMfas := []string{}
	secret := ""
	url := ""
	message := ""
	typeMfa := ""
	for _, item := range authenInfo.Mfas {
		if item.Type == "Totp" {
			if item.Enabled {
				if !item.Configured {
					secret = item.Secret
					url = item.Url
					message = "Please add your TOTP to your OTP Application now"
				} else {
					message = "Please enter your OTP from your OTP Application"
				}
				typeMfa = "Totp"
				break
			}
		} else if item.Type == "EmailOtp" {
			if item.Enabled {
				otp, err := util.GenerateCodeOtp()
				if err != nil {
					return "", "", "", "", "", nil, "", errutil.Wrapf(err, "generateCodeOtp")
				}
				err = inst.handler.RedisRepository.SetValueCache(fmt.Sprintf("email-otp-%s", userId), otp, inst.handler.TimeEmailOtp)
				if err != nil {
					return "", "", "", "", "", nil, "", errutil.Wrapf(err, "RedisRepository.SetValueCache")
				}
				err = util.SendMail([]string{item.PublicData}, fmt.Sprintf("Your OTP code is %d", otp))
				if err != nil {
					return "", "", "", "", "", nil, "", errutil.Wrapf(err, "util.SendMail")
				}
				message = "OTP sent to your email"
				typeMfa = "EmailOtp"
				break
			}
		}
	}
	for _, item := range authenInfo.Mfas {
		if item.Enabled {
			availbableMfas = append(availbableMfas, item.Type)
		}
	}
	return userContext.AccessToken(), requestId, secret, url, message, availbableMfas, typeMfa, nil
}

func (inst *ComponentsContainer) verifyMfa(userContext entity.UserContext, userId string, typeMfa string, otp int32) (bool, error) {
	otpCache := 0
	if typeMfa == "EmailOtp" {
		err := inst.handler.RedisRepository.GetValueCache(fmt.Sprintf("email-otp-%s", userId), &otpCache)
		if err != nil {
			return false, nil
		}
		if int32(otpCache) != otp {
			return false, nil
		}
		return true, nil
	}
	if typeMfa == "Totp" {
		authenInfo, err := inst.authenInfoRepository.GetByUserId(userContext, userId)
		if err != nil {
			return false, errutil.Wrapf(err, "authenInfoRepository.GetByUserId")
		}
		secret := ""
		configured := false
		index := -1
		mfa := &models.Mfa{}
		for key, item := range authenInfo.Mfas {
			if item.Type == "Totp" {
				mfa = item
				secret = item.Secret
				configured = item.Configured
				index = key
			}
		}
		valid := totp.Validate(strconv.Itoa(int(otp)), secret)
		if !configured && valid {
			mfa.Configured = true
			authenInfo.Mfas[index] = mfa
			err = inst.authenInfoRepository.UpdateOneByUserId(userContext, userId, map[string]interface{}{
				"Mfas": authenInfo.Mfas,
			})
			if err != nil {
				return false, errutil.Wrapf(err, "authenInfoRepository.UpdateOneByAttr")
			}
		}
		return valid, nil
	}
	return false, nil
}

func (inst *ComponentsContainer) Logout(userContext entity.UserContext) error {
	userId, err := entityutil.GetUserId(userContext)
	if err != nil {
		return errutil.Wrapf(err, "entityutil.GetUserId")
	}
	err = inst.handler.RedisRepository.SetValueCache(fmt.Sprintf("invalid-token-%s", userId), userContext.AccessToken(), inst.handler.Exp)
	if err != nil {
		return errutil.Wrapf(err, "RedisRepository.SetValueCache")
	}
	return nil
}
