package encryption

import (
	"testing"

	"github.com/innoai-tech/infra/pkg/configuration/testingutil"
	"github.com/octohelm/x/testing/bdd"
)

func TestEncrypter(t *testing.T) {
	t.Run("GIVEN prepare encryptor", bdd.GivenT(func(b bdd.T) {
		ctx, v := testingutil.BuildContext(t, func(v *struct {
			Encrypter
		}) {
		})

		b.When("do encrypt", func(b bdd.T) {
			encrypted, err := v.Encrypt(ctx, []byte("{}"))

			b.Then("encrypted success",
				bdd.NoError(err),
			)

			b.When("do decrypt", func(b bdd.T) {
				value, err := v.Decrypt(ctx, encrypted)
				b.Then("decrypt success",
					bdd.NoError(err),
				)
				b.Then("value recovered",
					bdd.Equal("{}", string(value)),
				)
			})
		})
	}))
}
