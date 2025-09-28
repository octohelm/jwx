package v1

import metav1 "github.com/octohelm/objectkind/pkg/apis/meta/v1"

type ProviderMetaList = metav1.List[ProviderMeta]

type ProviderCode string

type ProviderMeta struct {
	// 标识
	Code ProviderCode `json:"code"`
	// 名称
	Name string `json:"name"`
	// 登录入口
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitzero"`
}

type BindingList = metav1.List[Binding]

type Binding struct {
	Subject  string       `json:"sub"`
	Provider ProviderMeta `json:"provider"`
}
