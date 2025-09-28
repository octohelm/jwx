package v1

import (
	"testing"
)

func TestAuthorizations(t *testing.T) {
	auths := Authorization{}

	auths.Add("Bearer", "xxxxx")
	auths.Add("WechatBearer", "yyyyy")

	t.Log(auths.String())
}
