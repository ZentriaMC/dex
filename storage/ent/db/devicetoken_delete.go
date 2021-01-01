// Code generated by entc, DO NOT EDIT.

package db

import (
	"context"
	"fmt"

	"github.com/dexidp/dex/storage/ent/db/devicetoken"
	"github.com/dexidp/dex/storage/ent/db/predicate"
	"github.com/facebook/ent/dialect/sql"
	"github.com/facebook/ent/dialect/sql/sqlgraph"
	"github.com/facebook/ent/schema/field"
)

// DeviceTokenDelete is the builder for deleting a DeviceToken entity.
type DeviceTokenDelete struct {
	config
	hooks    []Hook
	mutation *DeviceTokenMutation
}

// Where adds a new predicate to the DeviceTokenDelete builder.
func (dtd *DeviceTokenDelete) Where(ps ...predicate.DeviceToken) *DeviceTokenDelete {
	dtd.mutation.predicates = append(dtd.mutation.predicates, ps...)
	return dtd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (dtd *DeviceTokenDelete) Exec(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(dtd.hooks) == 0 {
		affected, err = dtd.sqlExec(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DeviceTokenMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			dtd.mutation = mutation
			affected, err = dtd.sqlExec(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(dtd.hooks) - 1; i >= 0; i-- {
			mut = dtd.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, dtd.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// ExecX is like Exec, but panics if an error occurs.
func (dtd *DeviceTokenDelete) ExecX(ctx context.Context) int {
	n, err := dtd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (dtd *DeviceTokenDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: devicetoken.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: devicetoken.FieldID,
			},
		},
	}
	if ps := dtd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return sqlgraph.DeleteNodes(ctx, dtd.driver, _spec)
}

// DeviceTokenDeleteOne is the builder for deleting a single DeviceToken entity.
type DeviceTokenDeleteOne struct {
	dtd *DeviceTokenDelete
}

// Exec executes the deletion query.
func (dtdo *DeviceTokenDeleteOne) Exec(ctx context.Context) error {
	n, err := dtdo.dtd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{devicetoken.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (dtdo *DeviceTokenDeleteOne) ExecX(ctx context.Context) {
	dtdo.dtd.ExecX(ctx)
}
