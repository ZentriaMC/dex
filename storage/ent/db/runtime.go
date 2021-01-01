// Code generated by entc, DO NOT EDIT.

package db

import (
	"time"

	"github.com/dexidp/dex/storage/ent/db/authcode"
	"github.com/dexidp/dex/storage/ent/db/authrequest"
	"github.com/dexidp/dex/storage/ent/db/connector"
	"github.com/dexidp/dex/storage/ent/db/devicerequest"
	"github.com/dexidp/dex/storage/ent/db/devicetoken"
	"github.com/dexidp/dex/storage/ent/db/keys"
	"github.com/dexidp/dex/storage/ent/db/oauth2client"
	"github.com/dexidp/dex/storage/ent/db/offlinesession"
	"github.com/dexidp/dex/storage/ent/db/password"
	"github.com/dexidp/dex/storage/ent/db/refreshtoken"
	"github.com/dexidp/dex/storage/ent/schema"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	authcodeFields := schema.AuthCode{}.Fields()
	_ = authcodeFields
	// authcodeDescClientID is the schema descriptor for client_id field.
	authcodeDescClientID := authcodeFields[1].Descriptor()
	// authcode.ClientIDValidator is a validator for the "client_id" field. It is called by the builders before save.
	authcode.ClientIDValidator = authcodeDescClientID.Validators[0].(func(string) error)
	// authcodeDescNonce is the schema descriptor for nonce field.
	authcodeDescNonce := authcodeFields[3].Descriptor()
	// authcode.NonceValidator is a validator for the "nonce" field. It is called by the builders before save.
	authcode.NonceValidator = authcodeDescNonce.Validators[0].(func(string) error)
	// authcodeDescRedirectURI is the schema descriptor for redirect_uri field.
	authcodeDescRedirectURI := authcodeFields[4].Descriptor()
	// authcode.RedirectURIValidator is a validator for the "redirect_uri" field. It is called by the builders before save.
	authcode.RedirectURIValidator = authcodeDescRedirectURI.Validators[0].(func(string) error)
	// authcodeDescClaimsUserID is the schema descriptor for claims_user_id field.
	authcodeDescClaimsUserID := authcodeFields[5].Descriptor()
	// authcode.ClaimsUserIDValidator is a validator for the "claims_user_id" field. It is called by the builders before save.
	authcode.ClaimsUserIDValidator = authcodeDescClaimsUserID.Validators[0].(func(string) error)
	// authcodeDescClaimsUsername is the schema descriptor for claims_username field.
	authcodeDescClaimsUsername := authcodeFields[6].Descriptor()
	// authcode.ClaimsUsernameValidator is a validator for the "claims_username" field. It is called by the builders before save.
	authcode.ClaimsUsernameValidator = authcodeDescClaimsUsername.Validators[0].(func(string) error)
	// authcodeDescClaimsEmail is the schema descriptor for claims_email field.
	authcodeDescClaimsEmail := authcodeFields[7].Descriptor()
	// authcode.ClaimsEmailValidator is a validator for the "claims_email" field. It is called by the builders before save.
	authcode.ClaimsEmailValidator = authcodeDescClaimsEmail.Validators[0].(func(string) error)
	// authcodeDescClaimsPreferredUsername is the schema descriptor for claims_preferred_username field.
	authcodeDescClaimsPreferredUsername := authcodeFields[10].Descriptor()
	// authcode.DefaultClaimsPreferredUsername holds the default value on creation for the claims_preferred_username field.
	authcode.DefaultClaimsPreferredUsername = authcodeDescClaimsPreferredUsername.Default.(string)
	// authcodeDescConnectorID is the schema descriptor for connector_id field.
	authcodeDescConnectorID := authcodeFields[11].Descriptor()
	// authcode.ConnectorIDValidator is a validator for the "connector_id" field. It is called by the builders before save.
	authcode.ConnectorIDValidator = authcodeDescConnectorID.Validators[0].(func(string) error)
	// authcodeDescCodeChallenge is the schema descriptor for code_challenge field.
	authcodeDescCodeChallenge := authcodeFields[14].Descriptor()
	// authcode.DefaultCodeChallenge holds the default value on creation for the code_challenge field.
	authcode.DefaultCodeChallenge = authcodeDescCodeChallenge.Default.(string)
	// authcodeDescCodeChallengeMethod is the schema descriptor for code_challenge_method field.
	authcodeDescCodeChallengeMethod := authcodeFields[15].Descriptor()
	// authcode.DefaultCodeChallengeMethod holds the default value on creation for the code_challenge_method field.
	authcode.DefaultCodeChallengeMethod = authcodeDescCodeChallengeMethod.Default.(string)
	// authcodeDescID is the schema descriptor for id field.
	authcodeDescID := authcodeFields[0].Descriptor()
	// authcode.IDValidator is a validator for the "id" field. It is called by the builders before save.
	authcode.IDValidator = authcodeDescID.Validators[0].(func(string) error)
	authrequestFields := schema.AuthRequest{}.Fields()
	_ = authrequestFields
	// authrequestDescClaimsPreferredUsername is the schema descriptor for claims_preferred_username field.
	authrequestDescClaimsPreferredUsername := authrequestFields[14].Descriptor()
	// authrequest.DefaultClaimsPreferredUsername holds the default value on creation for the claims_preferred_username field.
	authrequest.DefaultClaimsPreferredUsername = authrequestDescClaimsPreferredUsername.Default.(string)
	// authrequestDescCodeChallenge is the schema descriptor for code_challenge field.
	authrequestDescCodeChallenge := authrequestFields[18].Descriptor()
	// authrequest.DefaultCodeChallenge holds the default value on creation for the code_challenge field.
	authrequest.DefaultCodeChallenge = authrequestDescCodeChallenge.Default.(string)
	// authrequestDescCodeChallengeMethod is the schema descriptor for code_challenge_method field.
	authrequestDescCodeChallengeMethod := authrequestFields[19].Descriptor()
	// authrequest.DefaultCodeChallengeMethod holds the default value on creation for the code_challenge_method field.
	authrequest.DefaultCodeChallengeMethod = authrequestDescCodeChallengeMethod.Default.(string)
	// authrequestDescID is the schema descriptor for id field.
	authrequestDescID := authrequestFields[0].Descriptor()
	// authrequest.IDValidator is a validator for the "id" field. It is called by the builders before save.
	authrequest.IDValidator = authrequestDescID.Validators[0].(func(string) error)
	connectorFields := schema.Connector{}.Fields()
	_ = connectorFields
	// connectorDescType is the schema descriptor for type field.
	connectorDescType := connectorFields[1].Descriptor()
	// connector.TypeValidator is a validator for the "type" field. It is called by the builders before save.
	connector.TypeValidator = connectorDescType.Validators[0].(func(string) error)
	// connectorDescName is the schema descriptor for name field.
	connectorDescName := connectorFields[2].Descriptor()
	// connector.NameValidator is a validator for the "name" field. It is called by the builders before save.
	connector.NameValidator = connectorDescName.Validators[0].(func(string) error)
	// connectorDescID is the schema descriptor for id field.
	connectorDescID := connectorFields[0].Descriptor()
	// connector.IDValidator is a validator for the "id" field. It is called by the builders before save.
	connector.IDValidator = connectorDescID.Validators[0].(func(string) error)
	devicerequestFields := schema.DeviceRequest{}.Fields()
	_ = devicerequestFields
	// devicerequestDescUserCode is the schema descriptor for user_code field.
	devicerequestDescUserCode := devicerequestFields[0].Descriptor()
	// devicerequest.UserCodeValidator is a validator for the "user_code" field. It is called by the builders before save.
	devicerequest.UserCodeValidator = devicerequestDescUserCode.Validators[0].(func(string) error)
	// devicerequestDescDeviceCode is the schema descriptor for device_code field.
	devicerequestDescDeviceCode := devicerequestFields[1].Descriptor()
	// devicerequest.DeviceCodeValidator is a validator for the "device_code" field. It is called by the builders before save.
	devicerequest.DeviceCodeValidator = devicerequestDescDeviceCode.Validators[0].(func(string) error)
	// devicerequestDescClientID is the schema descriptor for client_id field.
	devicerequestDescClientID := devicerequestFields[2].Descriptor()
	// devicerequest.ClientIDValidator is a validator for the "client_id" field. It is called by the builders before save.
	devicerequest.ClientIDValidator = devicerequestDescClientID.Validators[0].(func(string) error)
	// devicerequestDescClientSecret is the schema descriptor for client_secret field.
	devicerequestDescClientSecret := devicerequestFields[3].Descriptor()
	// devicerequest.ClientSecretValidator is a validator for the "client_secret" field. It is called by the builders before save.
	devicerequest.ClientSecretValidator = devicerequestDescClientSecret.Validators[0].(func(string) error)
	devicetokenFields := schema.DeviceToken{}.Fields()
	_ = devicetokenFields
	// devicetokenDescDeviceCode is the schema descriptor for device_code field.
	devicetokenDescDeviceCode := devicetokenFields[0].Descriptor()
	// devicetoken.DeviceCodeValidator is a validator for the "device_code" field. It is called by the builders before save.
	devicetoken.DeviceCodeValidator = devicetokenDescDeviceCode.Validators[0].(func(string) error)
	// devicetokenDescStatus is the schema descriptor for status field.
	devicetokenDescStatus := devicetokenFields[1].Descriptor()
	// devicetoken.StatusValidator is a validator for the "status" field. It is called by the builders before save.
	devicetoken.StatusValidator = devicetokenDescStatus.Validators[0].(func(string) error)
	keysFields := schema.Keys{}.Fields()
	_ = keysFields
	// keysDescID is the schema descriptor for id field.
	keysDescID := keysFields[0].Descriptor()
	// keys.IDValidator is a validator for the "id" field. It is called by the builders before save.
	keys.IDValidator = keysDescID.Validators[0].(func(string) error)
	oauth2clientFields := schema.OAuth2Client{}.Fields()
	_ = oauth2clientFields
	// oauth2clientDescSecret is the schema descriptor for secret field.
	oauth2clientDescSecret := oauth2clientFields[1].Descriptor()
	// oauth2client.SecretValidator is a validator for the "secret" field. It is called by the builders before save.
	oauth2client.SecretValidator = oauth2clientDescSecret.Validators[0].(func(string) error)
	// oauth2clientDescName is the schema descriptor for name field.
	oauth2clientDescName := oauth2clientFields[5].Descriptor()
	// oauth2client.NameValidator is a validator for the "name" field. It is called by the builders before save.
	oauth2client.NameValidator = oauth2clientDescName.Validators[0].(func(string) error)
	// oauth2clientDescLogoURL is the schema descriptor for logo_url field.
	oauth2clientDescLogoURL := oauth2clientFields[6].Descriptor()
	// oauth2client.LogoURLValidator is a validator for the "logo_url" field. It is called by the builders before save.
	oauth2client.LogoURLValidator = oauth2clientDescLogoURL.Validators[0].(func(string) error)
	// oauth2clientDescID is the schema descriptor for id field.
	oauth2clientDescID := oauth2clientFields[0].Descriptor()
	// oauth2client.IDValidator is a validator for the "id" field. It is called by the builders before save.
	oauth2client.IDValidator = oauth2clientDescID.Validators[0].(func(string) error)
	offlinesessionFields := schema.OfflineSession{}.Fields()
	_ = offlinesessionFields
	// offlinesessionDescUserID is the schema descriptor for user_id field.
	offlinesessionDescUserID := offlinesessionFields[1].Descriptor()
	// offlinesession.UserIDValidator is a validator for the "user_id" field. It is called by the builders before save.
	offlinesession.UserIDValidator = offlinesessionDescUserID.Validators[0].(func(string) error)
	// offlinesessionDescConnID is the schema descriptor for conn_id field.
	offlinesessionDescConnID := offlinesessionFields[2].Descriptor()
	// offlinesession.ConnIDValidator is a validator for the "conn_id" field. It is called by the builders before save.
	offlinesession.ConnIDValidator = offlinesessionDescConnID.Validators[0].(func(string) error)
	// offlinesessionDescID is the schema descriptor for id field.
	offlinesessionDescID := offlinesessionFields[0].Descriptor()
	// offlinesession.IDValidator is a validator for the "id" field. It is called by the builders before save.
	offlinesession.IDValidator = offlinesessionDescID.Validators[0].(func(string) error)
	passwordFields := schema.Password{}.Fields()
	_ = passwordFields
	// passwordDescEmail is the schema descriptor for email field.
	passwordDescEmail := passwordFields[0].Descriptor()
	// password.EmailValidator is a validator for the "email" field. It is called by the builders before save.
	password.EmailValidator = passwordDescEmail.Validators[0].(func(string) error)
	// passwordDescUsername is the schema descriptor for username field.
	passwordDescUsername := passwordFields[2].Descriptor()
	// password.UsernameValidator is a validator for the "username" field. It is called by the builders before save.
	password.UsernameValidator = passwordDescUsername.Validators[0].(func(string) error)
	// passwordDescUserID is the schema descriptor for user_id field.
	passwordDescUserID := passwordFields[3].Descriptor()
	// password.UserIDValidator is a validator for the "user_id" field. It is called by the builders before save.
	password.UserIDValidator = passwordDescUserID.Validators[0].(func(string) error)
	refreshtokenFields := schema.RefreshToken{}.Fields()
	_ = refreshtokenFields
	// refreshtokenDescClientID is the schema descriptor for client_id field.
	refreshtokenDescClientID := refreshtokenFields[1].Descriptor()
	// refreshtoken.ClientIDValidator is a validator for the "client_id" field. It is called by the builders before save.
	refreshtoken.ClientIDValidator = refreshtokenDescClientID.Validators[0].(func(string) error)
	// refreshtokenDescNonce is the schema descriptor for nonce field.
	refreshtokenDescNonce := refreshtokenFields[3].Descriptor()
	// refreshtoken.NonceValidator is a validator for the "nonce" field. It is called by the builders before save.
	refreshtoken.NonceValidator = refreshtokenDescNonce.Validators[0].(func(string) error)
	// refreshtokenDescClaimsUserID is the schema descriptor for claims_user_id field.
	refreshtokenDescClaimsUserID := refreshtokenFields[4].Descriptor()
	// refreshtoken.ClaimsUserIDValidator is a validator for the "claims_user_id" field. It is called by the builders before save.
	refreshtoken.ClaimsUserIDValidator = refreshtokenDescClaimsUserID.Validators[0].(func(string) error)
	// refreshtokenDescClaimsUsername is the schema descriptor for claims_username field.
	refreshtokenDescClaimsUsername := refreshtokenFields[5].Descriptor()
	// refreshtoken.ClaimsUsernameValidator is a validator for the "claims_username" field. It is called by the builders before save.
	refreshtoken.ClaimsUsernameValidator = refreshtokenDescClaimsUsername.Validators[0].(func(string) error)
	// refreshtokenDescClaimsEmail is the schema descriptor for claims_email field.
	refreshtokenDescClaimsEmail := refreshtokenFields[6].Descriptor()
	// refreshtoken.ClaimsEmailValidator is a validator for the "claims_email" field. It is called by the builders before save.
	refreshtoken.ClaimsEmailValidator = refreshtokenDescClaimsEmail.Validators[0].(func(string) error)
	// refreshtokenDescClaimsPreferredUsername is the schema descriptor for claims_preferred_username field.
	refreshtokenDescClaimsPreferredUsername := refreshtokenFields[9].Descriptor()
	// refreshtoken.DefaultClaimsPreferredUsername holds the default value on creation for the claims_preferred_username field.
	refreshtoken.DefaultClaimsPreferredUsername = refreshtokenDescClaimsPreferredUsername.Default.(string)
	// refreshtokenDescConnectorID is the schema descriptor for connector_id field.
	refreshtokenDescConnectorID := refreshtokenFields[10].Descriptor()
	// refreshtoken.ConnectorIDValidator is a validator for the "connector_id" field. It is called by the builders before save.
	refreshtoken.ConnectorIDValidator = refreshtokenDescConnectorID.Validators[0].(func(string) error)
	// refreshtokenDescToken is the schema descriptor for token field.
	refreshtokenDescToken := refreshtokenFields[12].Descriptor()
	// refreshtoken.DefaultToken holds the default value on creation for the token field.
	refreshtoken.DefaultToken = refreshtokenDescToken.Default.(string)
	// refreshtokenDescCreatedAt is the schema descriptor for created_at field.
	refreshtokenDescCreatedAt := refreshtokenFields[13].Descriptor()
	// refreshtoken.DefaultCreatedAt holds the default value on creation for the created_at field.
	refreshtoken.DefaultCreatedAt = refreshtokenDescCreatedAt.Default.(func() time.Time)
	// refreshtokenDescLastUsed is the schema descriptor for last_used field.
	refreshtokenDescLastUsed := refreshtokenFields[14].Descriptor()
	// refreshtoken.DefaultLastUsed holds the default value on creation for the last_used field.
	refreshtoken.DefaultLastUsed = refreshtokenDescLastUsed.Default.(func() time.Time)
	// refreshtokenDescID is the schema descriptor for id field.
	refreshtokenDescID := refreshtokenFields[0].Descriptor()
	// refreshtoken.IDValidator is a validator for the "id" field. It is called by the builders before save.
	refreshtoken.IDValidator = refreshtokenDescID.Validators[0].(func(string) error)
}
