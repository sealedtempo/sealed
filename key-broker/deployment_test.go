package keybroker_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// checkNamed returns the decision's last check called name.
func checkNamed(t *testing.T, d *keybroker.Decision, name string) keybroker.Check {
	t.Helper()
	for i := len(d.Checks) - 1; i >= 0; i-- {
		if d.Checks[i].Name == name {
			return d.Checks[i]
		}
	}
	t.Fatalf("no %s check in %+v", name, d.Checks)
	return keybroker.Check{}
}

// TestClosedDeploymentRefused (kb-1): a deployment the oracle has not registered yet (the first boot) and an Active
// one get their release. Once its customer closes it onchain, the same stack is refused with stack_not_approved at
// the deployment check: no secret is read and no key is derived, so a revived VM or a copied disk of a closed
// deployment never gets its diskKey or signerSeed again. A new deployment of the same releases (a new salt and its
// own approval) is not affected. Ported from the verifier's TestKBVerifyClosedDeploymentStillReleased, which got the
// same diskKey and signerSeed after closeDeployment.
func TestClosedDeploymentRefused(t *testing.T) {
	for name, mk := range registrars(t) {
		t.Run(name, func(t *testing.T) {
			w := kbtest.NewWorld(t, mk(t))
			s := w.Compose(t, kbtest.StackOptions{})
			w.Approve(t, s)
			h := newHarness(t, w, harnessOpts{})

			a := h.attempt(t, s)
			out := h.release(t, a)
			expectAllowed(t, out, a)
			if c := checkNamed(t, out.Decision, keybroker.CheckDeployment); !c.OK || c.Data["status"] != chain.DeploymentNone {
				t.Fatalf("first boot: %+v", c)
			}
			if out.Decision.Hashes.DeploymentID != s.Result.DeploymentID.Hex() {
				t.Fatalf("deployment %s, want %s", out.Decision.Hashes.DeploymentID, s.Result.DeploymentID.Hex())
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, head, err := w.Reg.Chain().Pin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			w.Register(t, s, uint64(head.Time.Unix()))
			a = h.attempt(t, s)
			out = h.release(t, a)
			expectAllowed(t, out, a)
			if c := checkNamed(t, out.Decision, keybroker.CheckDeployment); !c.OK || c.Data["status"] != chain.DeploymentActive {
				t.Fatalf("registered: %+v", c)
			}

			w.Close(t, s)
			reads := w.Secrets.Reads("sealed-notes-APP_SECRET")
			out = h.release(t, h.attempt(t, s))
			d := expectDenied(t, out, http.StatusForbidden, keybroker.ReasonStackNotApproved)
			last := out.Decision.Checks[len(out.Decision.Checks)-1]
			if last.Name != keybroker.CheckDeployment || last.Data["status"] != chain.DeploymentClosed || !strings.Contains(d.Detail, "closed onchain") {
				t.Fatalf("failing check %+v (%s)", last, d.Detail)
			}
			if out.Decision.Released != nil || w.Secrets.Reads("sealed-notes-APP_SECRET") != reads {
				t.Fatal("secrets read or released for a closed deployment")
			}
			if h.log.Last() == nil || h.log.Last().RequestID != out.Decision.RequestID {
				t.Fatal("the denial was not logged")
			}

			// The customer's next deployment of the same releases: a new salt, so a new stack and deploymentId.
			s2 := w.Compose(t, kbtest.StackOptions{Edit: func(c *composer.Config) { c.Salt = "0x" + strings.Repeat("6b", 32) }})
			w.Approve(t, s2)
			a = h.attempt(t, s2)
			expectAllowed(t, h.release(t, a), a)
		})
	}
}

// deploymentsDown is a chain whose getDeployment calls fail (an RPC error on that one read).
type deploymentsDown struct{ *kbtest.MemChain }

func (c deploymentsDown) Pin(ctx context.Context) (keybroker.Registry, keybroker.Head, error) {
	_, head, err := c.MemChain.Pin(ctx)
	return c, head, err
}

func (c deploymentsDown) GetDeployment(context.Context, [32]byte) (*chain.Deployment, error) {
	return nil, errors.New("connection reset by peer")
}

// TestDeploymentReadFails (kb-1): a failed getDeployment read is an RPC failure, 503 unavailable, never a release.
func TestDeploymentReadFails(t *testing.T) {
	reg := kbtest.NewMemRegistrar()
	w := kbtest.NewWorld(t, reg)
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	h := newHarness(t, w, harnessOpts{chain: deploymentsDown{reg.C}})
	out := h.release(t, h.attempt(t, s))
	expectDenied(t, out, http.StatusServiceUnavailable, keybroker.ReasonUnavailable)
	if last := out.Decision.Checks[len(out.Decision.Checks)-1]; last.Name != keybroker.CheckDeployment || out.Decision.Released != nil {
		t.Fatalf("failing check %+v", last)
	}
}
