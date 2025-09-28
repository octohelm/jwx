gen:
    go generate ./pkg/...

test:
    CGO_ENABLED=0 \
      go test -failfast -count=1 ./pkg/...

fmt:
    go tool gofumpt -w -l .
