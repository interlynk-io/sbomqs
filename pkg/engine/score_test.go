package engine

import (
	"context"
	"errors"
	"testing"
)

func TestProcessFile(t *testing.T) {
	testCases := []struct {
		name        string
		ctx         context.Context
		ep          Params
		expectedErr error
	}{
		{
			name: "happy-path",
			ctx:  context.Background(),
			ep: Params{
				Path: []string{"./sbomqs-spdx-syft.json"},
			},
			expectedErr: nil,
		},
		{
			name: "happy-path-category",
			ctx:  context.Background(),
			ep: Params{
				Path:     []string{"./sbomqs-spdx-syft.json"},
				Category: "NTIA-minimum-elements",
			},
			expectedErr: nil,
		},
		{
			name: "happy-path-basic",
			ctx:  context.Background(),
			ep: Params{
				Path:     []string{"./sbomqs-spdx-syft.json"},
				Category: "NTIA-minimum-elements",
				Basic:    true,
			},
			expectedErr: nil,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := processFile(test.ctx, &test.ep, test.ep.Path[0])
			if !errors.Is(err, test.expectedErr) {
				t.Errorf("expected error (%v), got error (%v)", test.expectedErr, err)
			}
		})
	}
}
