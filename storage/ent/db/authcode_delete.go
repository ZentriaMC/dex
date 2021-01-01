// Code generated by entc, DO NOT EDIT.

package db

import (
	"context"
	"fmt"

	"github.com/dexidp/dex/storage/ent/db/authcode"
	"github.com/dexidp/dex/storage/ent/db/predicate"
	"github.com/facebook/ent/dialect/sql"
	"github.com/facebook/ent/dialect/sql/sqlgraph"
	"github.com/facebook/ent/schema/field"
)

// AuthCodeDelete is the builder for deleting a AuthCode entity.
type AuthCodeDelete struct {
	config
	hooks    []Hook
	mutation *AuthCodeMutation
}

// Where adds a new predicate to the AuthCodeDelete builder.
func (acd *AuthCodeDelete) Where(ps ...predicate.AuthCode) *AuthCodeDelete {
	acd.mutation.predicates = append(acd.mutation.predicates, ps...)
	return acd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (acd *AuthCodeDelete) Exec(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(acd.hooks) == 0 {
		affected, err = acd.sqlExec(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*AuthCodeMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			acd.mutation = mutation
			affected, err = acd.sqlExec(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(acd.hooks) - 1; i >= 0; i-- {
			mut = acd.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, acd.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// ExecX is like Exec, but panics if an error occurs.
func (acd *AuthCodeDelete) ExecX(ctx context.Context) int {
	n, err := acd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (acd *AuthCodeDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: authcode.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: authcode.FieldID,
			},
		},
	}
	if ps := acd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return sqlgraph.DeleteNodes(ctx, acd.driver, _spec)
}

// AuthCodeDeleteOne is the builder for deleting a single AuthCode entity.
type AuthCodeDeleteOne struct {
	acd *AuthCodeDelete
}

// Exec executes the deletion query.
func (acdo *AuthCodeDeleteOne) Exec(ctx context.Context) error {
	n, err := acdo.acd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{authcode.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (acdo *AuthCodeDeleteOne) ExecX(ctx context.Context) {
	acdo.acd.ExecX(ctx)
}
