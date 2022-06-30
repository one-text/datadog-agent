package session

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetNextColumnOid(t *testing.T) {
	tests := []struct {
		oid         string
		expectedOid string
		expectedErr string
	}{
		{
			oid:         "1.3.6.1.2.1.2.2.1.2.99",
			expectedOid: "1.3.6.1.2.1.2.2.1.3",
		},
		{
			oid:         "1.3.6.1.2.1.2.2.1.99.99",
			expectedOid: "1.3.6.1.2.1.2.2.1.100",
		},
		{
			oid:         "1.3.6.1.2.1.2.2.1.1.1",
			expectedOid: "1.3.6.1.2.1.2.2.1.2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.oid, func(t *testing.T) {
			newOid, err := GetNextColumnOid(tt.oid)
			assert.Equal(t, tt.expectedOid, newOid)

			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
