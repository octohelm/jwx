package v1

import (
	"fmt"
	"time"

	"github.com/octohelm/courier/pkg/statuserror"
)

type ErrUnsupportedGrantType struct {
	statuserror.Forbidden

	GrantType string
}

func (e *ErrUnsupportedGrantType) Error() string {
	return fmt.Sprintf("不支持的 OAuth 授权类型 %s", e.GrantType)
}

type ErrWrongPasswordTooManyTimes struct {
	statuserror.TooManyRequests

	Wait time.Duration
}

func (e *ErrWrongPasswordTooManyTimes) Error() string {
	return fmt.Sprintf("密码错误太多次，请 %s 后重试", e.Wait)
}

type ErrAccountAlreadyLogout struct {
	statuserror.Forbidden
}

func (*ErrAccountAlreadyLogout) Error() string {
	return "账户已登出"
}

type ErrInvalidToken struct {
	statuserror.Unauthorized

	Reason error
}

func (e *ErrInvalidToken) Error() string {
	if e.Reason != nil {
		return fmt.Sprintf("无效访问凭证: %s", e.Reason)
	}

	return "无效访问凭证"
}

type ErrInvalidUserOrPassword struct {
	statuserror.Forbidden
}

func (*ErrInvalidUserOrPassword) Error() string {
	return "用户名或密码错误"
}

type ErrInvalidClientID struct {
	statuserror.Forbidden
}

func (*ErrInvalidClientID) Error() string {
	return "无效的 client_id"
}

type ErrInvalidCaptcha struct {
	statuserror.Forbidden
}

func (e *ErrInvalidCaptcha) Error() string {
	return fmt.Sprintf("验证码错误")
}

type ErrBadAuthorizationCodeGrant struct {
	statuserror.BadRequest

	Reason error
}

func (e *ErrBadAuthorizationCodeGrant) Error() string {
	return fmt.Sprintf("无效的授权码: %s", e.Reason)
}

type ErrAdministratorRequired struct {
	statuserror.Forbidden
}

func (e *ErrAdministratorRequired) Error() string {
	return fmt.Sprintf("务必是管理员")
}
