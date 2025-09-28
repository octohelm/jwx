package sign

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/innoai-tech/infra/pkg/configuration/testingutil"
	"github.com/octohelm/jwx/pkg/jwk"
	"github.com/octohelm/objectkind/pkg/idgen"
	"github.com/octohelm/x/testing/bdd"
)

func TestSigner(t *testing.T) {
	ctx, d := testingutil.BuildContext(t, func(t *struct {
		idgen.IDGen
		jwk.KeySet

		JWTSigner
	}) {
	})

	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyset, _ := d.TypedPublicSet()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.MarshalWrite(w, keyset)

		return
	}))
	t.Cleanup(svc.Close)

	bdd.FromT(t).Given("signer", func(b bdd.T) {
		b.When("sign a token", func(b bdd.T) {
			tokStr, _, err := d.Sign(ctx,
				WithExpiresIn(5*time.Second),
				WithSubject("test"),
				WithClaim("sub_typ", "CLIENT"),
			)

			b.Then("success",
				bdd.NoError(err),
			)

			b.When("validate", func(b bdd.T) {
				tok, err := d.Validate(ctx, tokStr)

				b.Then("be valid",
					bdd.NoError(err),
					bdd.Equal("test", tok.Subject()),
				)
			})

			b.When("validate with claim", func(b bdd.T) {
				tok, err := d.Validate(ctx, tokStr,
					WithClaimExpect("sub_typ", "CLIENT"),
				)

				b.Then("be valid",
					bdd.NoError(err),
					bdd.Equal("test", tok.Subject()),
				)
			})

			b.When("validate by jwks", func(b bdd.T) {
				_, v2 := testingutil.BuildContext(t, func(v *struct {
					JWTValidator
				},
				) {
					v.JwksEndpoint = svc.URL
				})

				tok, err := v2.Validate(ctx, tokStr)

				b.Then("be valid",
					bdd.NoError(err),
					bdd.Equal("test", tok.Subject()),
				)
			})
		})
	})
}
