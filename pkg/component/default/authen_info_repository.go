package defaultcomponent

import (
	"github.com/thteam47/common-libs/confg"
	"github.com/thteam47/common-libs/mongoutil"
	"github.com/thteam47/common/entity"
	"github.com/thteam47/common/pkg/mongorepository"
	"github.com/thteam47/go-identity-authen-api/errutil"
	"github.com/thteam47/go-identity-authen-api/pkg/models"
)

type AuthenInfoRepository struct {
	config         *AuthenInfoRepositoryConfig
	baseRepository *mongorepository.BaseRepository
}

type AuthenInfoRepositoryConfig struct {
	MongoClientWrapper *mongoutil.MongoClientWrapper `mapstructure:"mongo-client-wrapper"`
}

func NewAuthenInfoRepositoryWithConfig(properties confg.Confg) (*AuthenInfoRepository, error) {
	config := AuthenInfoRepositoryConfig{}
	err := properties.Unmarshal(&config)
	if err != nil {
		return nil, errutil.Wrap(err, "Unmarshal")
	}

	mongoClientWrapper, err := mongoutil.NewBaseMongoClientWrapperWithConfig(properties.Sub("mongo-client-wrapper"))
	if err != nil {
		return nil, errutil.Wrap(err, "NewBaseMongoClientWrapperWithConfig")
	}
	return NewBaseAuthenInfoRepository(&AuthenInfoRepositoryConfig{
		MongoClientWrapper: mongoClientWrapper,
	})
}

func NewBaseAuthenInfoRepository(config *AuthenInfoRepositoryConfig) (*AuthenInfoRepository, error) {
	inst := &AuthenInfoRepository{
		config: config,
	}

	var err error
	inst.baseRepository, err = mongorepository.NewBaseRepository(&mongorepository.BaseRepositoryConfig{
		MongoClientWrapper: inst.config.MongoClientWrapper,
		Prototype:          models.AuthenInfo{},
		MongoIdField:       "Id",
		IdField:            "AuthenInfoId",
	})
	if err != nil {
		return nil, errutil.Wrap(err, "mongorepository.NewBaseRepository")
	}

	return inst, nil
}

// func getAuthenInfo(item *pb.AuthenInfo) (*models.AuthenInfo, error) {
// 	if item == nil {
// 		return nil, nil
// 	}
// 	authenInfo := &models.AuthenInfo{}
// 	err := util.FromMessage(item, authenInfo)
// 	if err != nil {
// 		return nil, errutil.Wrap(err, "FromMessage")
// 	}
// 	return authenInfo, nil
// }

//	func makeAuthenInfo(item *models.AuthenInfo) (*pb.AuthenInfo, error) {
//		authenInfo := &pb.AuthenInfo{}
//		err := util.ToMessage(item, authenInfo)
//		if err != nil {
//			return nil, errutil.Wrap(err, "ToMessage")
//		}
//		return authenInfo, nil
//	}
func (inst *AuthenInfoRepository) Create(userContext entity.UserContext, item *models.AuthenInfo) (*models.AuthenInfo, error) {
	err := inst.baseRepository.Create(userContext, item, nil)
	if err != nil {
		return nil, errutil.Wrap(err, "Create")
	}
	return item, nil
}

func (inst *AuthenInfoRepository) GetOneByFindRequest(userContext entity.UserContext, findRequest *entity.FindRequest) (*models.AuthenInfo, error) {
	if findRequest == nil {
		findRequest = &entity.FindRequest{}
	}
	item := &models.AuthenInfo{}
	err := inst.baseRepository.FindOneByFindRequest(userContext, findRequest, &mongorepository.FindOptions{}, &item)
	if err != nil {
		return nil, errutil.Wrap(err, "FindOneByFindRequest")
	}
	return item, nil
}

func (inst *AuthenInfoRepository) GetByUserId(userContext entity.UserContext, userId string) (*models.AuthenInfo, error) {
	item := &models.AuthenInfo{}
	err := inst.baseRepository.FindOneByAttribute(userContext, "UserId", userId, &mongorepository.FindOptions{}, &item)
	if err != nil {
		return nil, errutil.Wrap(err, "FindOneByFindRequest")
	}
	return item, nil
}

// func (inst *AuthenInfoRepository) ChangeActionUser(idUser string, role string, a []string) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	var roleUser string
// 	if role == "" {
// 		roleUser = "staff"
// 	} else {
// 		roleUser = role
// 	}
// 	var actionList []string
// 	if roleUser == "admin" {
// 		actionList = append(actionList, "All Rights")
// 	} else if roleUser == "assistant" {
// 		actionList = []string{"Add Server", "Update Server", "Detail Status", "Export", "Connect", "Disconnect", "Delete Server", "Change Password"}
// 	} else {
// 		actionList = a
// 	}
// 	id, _ := primitive.ObjectIDFromHex(idUser)
// 	filterUser := bson.M{"_id": id}
// 	updateUser := bson.M{"$set": bson.M{
// 		"role":   roleUser,
// 		"action": actionList,
// 	}}
// 	_, err := inst.MongoDB.Collection(vi.GetString("collectionUser")).UpdateOne(ctx, filterUser, updateUser)
// 	if err != nil {
// 		return err
// 	}

//		return nil
//	}

func (inst *AuthenInfoRepository) UpdateOneByUserId(userContext entity.UserContext, userId string, data map[string]interface{}) error {
	err := inst.baseRepository.UpdateOneByAttribute(userContext, "UserId", userId, data, nil, &mongorepository.UpdateOptions{InsertIfNotExisted: true})
	if err != nil {
		return errutil.Wrap(err, "FindOneByFindRequest")
	}
	return nil
}

// func (u *AuthenInfoRepository) ChangePassUser(idUser string, pass string) error {
// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// defer cancel()
// var id primitive.ObjectID
// id, _ = primitive.ObjectIDFromHex(idUser)

// passHash, _ := drive.HashPassword(pass)
// filterUser := bson.M{"_id": id}
//
//	updateUser := bson.M{"$set": bson.M{
//		"password": passHash,
//	}}
//
// _, err := u.MongoDB.UpdateOne(ctx, filterUser, updateUser)
//
//	if err != nil {
//		return err
//	}
//
//		return nil
//	}

// func (inst *AuthenInfoRepository) DeleteOneByUserId(userContext entity.UserContext, id string) error {
// 	_, err := inst.handler.MongoDB.DeleteOne(context.Background(), bson.M{"user_id": id})

// 	if err != nil {
// 		return errutil.Wrap(err, "MongoDB.DeleteOne")
// 	}
// 	return nil
// }

// func (inst *AuthenInfoRepository) ForgotPassword(userContext entity.UserContext, data string) (string, error) {
// 	userItem, err := inst.userService.FindByLoginName(userContext, data)
// 	if err != nil {
// 		return "", errutil.Wrapf(err, "userService.FindByLoginName")
// 	}
// 	if userItem == nil {
// 		return "", errutil.NewWithMessage("Username or password incorrect")
// 	}
// 	tokenInfo := &models.TokenInfo{
// 		AuthenticationDone: true,
// 		UserId:             userItem.UserId,
// 		Exp:                int32(time.Now().Add(5 * time.Minute).Unix()),
// 	}
// 	token, err := inst.jwtRepository.Generate(tokenInfo)
// 	if err != nil {
// 		return "", errutil.Wrapf(err, "jwtRepository.Generate")
// 	}
// 	dataMail, err := util.ParseTemplate("../util/template.html", map[string]string{
// 		"message":    "Click the link to change password.",
// 		"username":   userItem.FullName,
// 		"title":      "Forgot Password",
// 		"buttonText": "Change Passowrd Now",
// 		"link":       fmt.Sprintf("http://localhost:4200/update-password/%s", token),
// 	})
// 	if err != nil {
// 		return "", errutil.Wrapf(err, "util.ParseTemplate")
// 	}
// 	err = util.SendMail([]string{userItem.Email}, dataMail)
// 	if err != nil {
// 		return "", errutil.Wrapf(err, "util.SendMail")
// 	}
// 	return fmt.Sprintf("Click the link in your email %s to change your password", userItem.Email), nil
// }

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
