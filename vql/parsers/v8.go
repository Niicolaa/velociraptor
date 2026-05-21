/*
   Velociraptor - Dig Deeper
   Copyright (C) 2019-2025 Rapid7 Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package parsers

import (
	"context"

	"github.com/Velocidex/ordereddict"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/parsers/v8"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

type V8DeserializeArgs struct {
	Data string `vfilter:"required,field=data,doc=The V8 serialized (structured clone) blob to decode. This is typically an IndexedDB value."`
}

type V8DeserializeFunction struct{}

func (self V8DeserializeFunction) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) vfilter.Any {

	arg := &V8DeserializeArgs{}
	err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
	if err != nil {
		scope.Log("v8_deserialize: %v", err)
		return &vfilter.Null{}
	}

	result, err := v8.Deserialize([]byte(arg.Data))
	if err != nil {
		scope.Log("DEBUG:v8_deserialize: %v", err)
		return &vfilter.Null{}
	}

	if result == nil {
		return &vfilter.Null{}
	}

	return result
}

func (self V8DeserializeFunction) Info(
	scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.FunctionInfo {
	return &vfilter.FunctionInfo{
		Name:    "v8_deserialize",
		Doc:     "Decode a V8 structured clone (SerializedScriptValue) blob into a native data structure. Used to decode IndexedDB values stored by Chromium/Electron applications.",
		ArgType: type_map.AddType(scope, &V8DeserializeArgs{}),
	}
}

func init() {
	vql_subsystem.RegisterFunction(&V8DeserializeFunction{})
}
