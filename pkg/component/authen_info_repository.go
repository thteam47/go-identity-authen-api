package component

import (
	"github.com/thteam47/common/entity"
	"github.com/thteam47/go-identity-authen-api/pkg/models"
)

type AuthenInfoRepository interface {
	// GetAll(userContext entity.UserContext, number int32, limit int32) ([]*models.User, error)
	// Count(userContext entity.UserContext) (int32, error)
	GetOneByFindRequest(userContext entity.UserContext, findRequest *entity.FindRequest) (*models.AuthenInfo, error)
	Create(userContext entity.UserContext, item *models.AuthenInfo) (*models.AuthenInfo, error)
	UpdateOneByUserId(userContext entity.UserContext, userId string, data map[string]interface{}) error
	GetByUserId(userContext entity.UserContext, userId string) (*models.AuthenInfo, error)
	//DeleteOneByUserId(userContext entity.UserContext, id string) error
	//ForgotPassword(userContext entity.UserContext, data string) (string, error)
	//RegisterUser(userContext entity.UserContext, username string, fullName string, email string) (string, error)
}
