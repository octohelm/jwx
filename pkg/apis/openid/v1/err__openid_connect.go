package v1

import (
	"fmt"

	"github.com/octohelm/courier/pkg/statuserror"
)

type ErrInvalidOpenidConnect struct {
	statuserror.BadRequest

	Reason error
}

func (e *ErrInvalidOpenidConnect) Error() string {
	return fmt.Sprintf("Openid 登录异常: %s", e.Reason)
}

type ErrOpenidBindingConflict struct {
	statuserror.Conflict

	Provider ProviderCode
	Subject  string
}

func (e *ErrOpenidBindingConflict) Error() string {
	return fmt.Sprintf("%s@%s 已绑定", e.Subject, e.Provider)
}
