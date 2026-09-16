// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build windows

package eventlog

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tianlin/go-windows-eventlog/pkg/wineventlog"
)

func TestIsRecoverable(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		isFile      bool
		recoverable bool
	}{
		{name: "wrapped ETW native error", err: fmt.Errorf("ProcessTrace: %w", wineventlog.ERROR_INVALID_HANDLE), recoverable: true},
		{
			name:        "ERROR_INVALID_HANDLE",
			err:         wineventlog.ERROR_INVALID_HANDLE,
			isFile:      false,
			recoverable: true,
		},
		{
			name:        "RPC_S_SERVER_UNAVAILABLE",
			err:         wineventlog.RPC_S_SERVER_UNAVAILABLE,
			isFile:      false,
			recoverable: true,
		},
		{
			name:        "RPC_S_CALL_CANCELLED",
			err:         wineventlog.RPC_S_CALL_CANCELLED,
			isFile:      false,
			recoverable: true,
		},
		{
			name:        "ERROR_EVT_QUERY_RESULT_STALE",
			err:         wineventlog.ERROR_EVT_QUERY_RESULT_STALE,
			isFile:      false,
			recoverable: true,
		},
		{
			name:        "ERROR_INVALID_PARAMETER",
			err:         wineventlog.ERROR_INVALID_PARAMETER,
			isFile:      false,
			recoverable: true,
		},
		{
			name:        "ERROR_EVT_PUBLISHER_DISABLED",
			err:         wineventlog.ERROR_EVT_PUBLISHER_DISABLED,
			isFile:      false,
			recoverable: true,
		},
		{
			name:        "io.EOF for channel (not file)",
			err:         io.EOF,
			isFile:      false,
			recoverable: false,
		},
		{
			name:        "io.EOF for file",
			err:         io.EOF,
			isFile:      true,
			recoverable: false,
		},
		{
			name:        "ERROR_EVT_CHANNEL_NOT_FOUND for channel (not file)",
			err:         wineventlog.ERROR_EVT_CHANNEL_NOT_FOUND,
			isFile:      false,
			recoverable: true,
		},
		{
			name:        "ERROR_EVT_CHANNEL_NOT_FOUND for file",
			err:         wineventlog.ERROR_EVT_CHANNEL_NOT_FOUND,
			isFile:      true,
			recoverable: false,
		},
		{
			name:        "other error",
			err:         errors.New("some other error"),
			isFile:      false,
			recoverable: false,
		},
		{
			name:        "nil error",
			err:         nil,
			isFile:      false,
			recoverable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRecoverable(tt.err, tt.isFile)
			assert.Equal(t, tt.recoverable, result)
		})
	}
}
