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

	"github.com/tianlin/go-windows-eventlog/pkg/wineventlog"
)

// IsRecoverable returns a boolean indicating whether the error represents
// a condition where the Windows Event Log session can be recovered through a
// reset and reopening of the handle (Reset, Open).
func IsRecoverable(err error, isFile bool) bool {
	return errors.Is(err, wineventlog.ERROR_INVALID_HANDLE) ||
		errors.Is(err, wineventlog.RPC_S_SERVER_UNAVAILABLE) ||
		errors.Is(err, wineventlog.RPC_S_CALL_CANCELLED) ||
		errors.Is(err, wineventlog.ERROR_EVT_QUERY_RESULT_STALE) ||
		errors.Is(err, wineventlog.ERROR_INVALID_PARAMETER) ||
		errors.Is(err, wineventlog.ERROR_EVT_PUBLISHER_DISABLED) ||
		errors.Is(err, errRecordIDGap) ||
		errors.Is(err, errRenderNoEvent) ||
		(!isFile && errors.Is(err, wineventlog.ERROR_EVT_CHANNEL_NOT_FOUND))
}
