package cipher

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"maps"
	"testing"

	"github.com/octohelm/x/testing/bdd"
)

func TestCipher(t *testing.T) {
	b := bdd.FromT(t)

	for alg := range maps.Keys(cipherFactories) {
		b.Given(fmt.Sprintf("cipher for %s", alg), func(b bdd.T) {
			key, nonce := bdd.Must2(NewKeyNonce(alg))

			b.When("do encrypt", func(b bdd.T) {
				c := bdd.Must(FromKeyNonce(alg, key, nonce))

				data, _ := io.ReadAll(io.LimitReader(rand.Reader, 10240))

				encrypted, err := io.ReadAll(
					TransformReader(bytes.NewReader(data), c.EncryptWriter),
				)
				b.Then("success",
					bdd.NoError(err),
					bdd.Equal(len(data), len(encrypted)),
				)

				b.When("do decrypt", func(b bdd.T) {
					c := bdd.Must(FromKeyNonce(alg, key, nonce))

					ret := bytes.NewBuffer(nil)

					wc := bdd.Must(c.DecryptWriter(ret))
					_, err := io.Copy(wc, bytes.NewReader(encrypted))

					b.Then("success",
						bdd.NoError(err),
						bdd.Equal(string(data), ret.String()),
					)
				})
			})
		})
	}
}
