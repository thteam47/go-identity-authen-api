package grpcapp

import (
	"context"
	grpcauth "github.com/thteam47/common/grpcutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"

	"github.com/thteam47/go-identity-authen-api/errutil"
	"github.com/thteam47/go-identity-authen-api/pkg/models"
	pb "github.com/thteam47/common/api/identity-authen-api"
	"github.com/thteam47/go-identity-authen-api/util"
	"golang.org/x/exp/slices"
)

func getMfa(item *pb.Mfa) (*models.Mfa, error) {
	if item == nil {
		return nil, nil
	}
	user := &models.Mfa{}
	err := util.FromMessage(item, user)
	if err != nil {
		return nil, errutil.Wrap(err, "FromMessage")
	}
	return user, nil
}

func getMfas(items []*pb.Mfa) ([]*models.Mfa, error) {
	mfas := []*models.Mfa{}
	for _, item := range items {
		mfa, err := getMfa(item)
		if err != nil {
			return nil, errutil.Wrap(err, "getMfas")
		}
		mfas = append(mfas, mfa)
	}
	return mfas, nil
}

func makeMfa(item *models.Mfa) (*pb.Mfa, error) {
	mfa := &pb.Mfa{}
	err := util.ToMessage(item, mfa)
	if err != nil {
		return nil, errutil.Wrap(err, "ToMessage")
	}
	return mfa, nil
}

func makeMfas(items []*models.Mfa) ([]*pb.Mfa, error) {
	mfas := []*pb.Mfa{}
	for _, item := range items {
		mfa, err := makeMfa(item)
		if err != nil {
			return nil, errutil.Wrap(err, "makeMfa")
		}
		mfas = append(mfas, mfa)
	}
	return mfas, nil
}
func (inst *IdentityAuthenService) GetMfaType(ctx context.Context, req *pb.StringRequest) (*pb.MfaResponse, error) {
	userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "identity-authen-api:authen-info", "update", &grpcauth.AuthenOption{})
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}
	userId := strings.TrimSpace(req.Value)
	authenInfo, err := inst.componentsContainer.AuthenInfoRepository().GetByUserId(userContext, userId)
	if err != nil {
		return nil, errutil.Wrapf(err, "authenInfoRepository.GetOneByAttr(")
	}

	mfas, err := makeMfas(authenInfo.Mfas)
	if err != nil {
		return nil, errutil.Wrapf(err, "makeMfas")
	}
	return &pb.MfaResponse{
		Mfas: mfas,
	}, nil

}

func (inst *IdentityAuthenService) UpdateMfa(ctx context.Context, req *pb.UpdateMfaRequest) (*pb.MessageResponse, error) {
	userContext, err := inst.componentsContainer.AuthService().Authentication(ctx, req.Ctx.AccessToken, req.Ctx.DomainId, "identity-authen-api:authen-info", "update", &grpcauth.AuthenOption{})
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, errutil.Message(err))
	}

	userId := strings.TrimSpace(req.UserId)
	mfas, err := getMfas(req.Mfas)
	if err != nil {
		return nil, errutil.Wrapf(err, "getMfas")
	}
	mfasValid := []*models.Mfa{}
	typeMfas := []string{"Totp", "EmailOtp"}
	for _, item := range mfas {
		if slices.Contains(typeMfas, strings.TrimSpace(item.Type)) {
			if strings.TrimSpace(item.Type) == "Totp" {
				hash, err := util.HashPassword(userId)
				if err != nil {
					return nil, errutil.Wrapf(err, "util.HashPassword")
				}
				key, err := util.GenerateTotp(hash)
				if err != nil {
					return nil, errutil.Wrapf(err, "util.GenerateTotp")
				}
				item.Secret = key.Secret()
				if err != nil {
					return nil, errutil.Wrapf(err, "util.HashPassword")
				}
				item.Url = key.URL()
			}
			item.PublicData = strings.TrimSpace(strings.ToLower(item.PublicData))
			mfasValid = append(mfasValid, item)
		}
	}

	if len(mfasValid) == 0 {
		return &pb.MessageResponse{}, nil
	}

	err = inst.componentsContainer.AuthenInfoRepository().UpdateOneByUserId(userContext, userId, map[string]interface{}{
		"mfas": mfasValid,
	})
	if err != nil {
		return nil, errutil.Wrapf(err, "authenInfoRepository.UpdateOneByAttr(")
	}
	return &pb.MessageResponse{
		Ok:      true,
		Message: "Update mfa successful",
	}, nil

}
