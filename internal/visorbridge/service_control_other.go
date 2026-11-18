//go:build !linux

package visorbridge

import "context"

func (b *Bridge) serviceContext() (map[string]any, error)                        { return nil, refused }
func (b *Bridge) restartService(context.Context, []byte, []byte) ([]byte, error) { return nil, refused }
