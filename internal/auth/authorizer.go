package auth

import (
	"fmt"

	"github.com/casbin/casbin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Authorizer struct {
	enforcer *casbin.Enforcer
}

func New(model, policy string) *Authorizer {
	return &Authorizer{
		enforcer: casbin.NewEnforcer(model, policy),
	}
}

func (a *Authorizer) Authorize(subject, object, action string) error {
	if a.enforcer.Enforce(subject, object, action) {
		return nil
	}
	msg := fmt.Sprintf(
		"%s not permitted to %s to %s",
		subject,
		action,
		object,
	)
	return status.New(codes.PermissionDenied, msg).Err()
}
