package clientutil

import (
	"context"

	"github.com/octohelm/courier/pkg/courier"
)

type Response[Data any] interface {
	ResponseData() *Data
}

type Resp[Data any] struct{}

func (Resp[Data]) ResponseData() *Data {
	return new(Data)
}

func DoWith[Data any, Op Response[Data]](
	ctx context.Context,
	c courier.Client,
	build func(req *Op),
) (*Data, error) {
	req := new(Op)
	build(req)

	resp := new(Data)
	if _, ok := any(resp).(*courier.NoContent); ok {
		_, err := c.Do(ctx, req).Into(nil)
		return resp, err
	}

	_, err := c.Do(ctx, req).Into(resp)
	return resp, err
}
