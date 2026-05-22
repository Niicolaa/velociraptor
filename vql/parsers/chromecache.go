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
	"fmt"
	"io"
	"regexp"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/accessors"
	"www.velocidex.com/golang/velociraptor/acls"
	utils "www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/velociraptor/vql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/parsers/chromecache"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

// Cap the size of an external/body payload we will read fully into
// memory so a single huge cached object cannot exhaust memory.
const maxCacheFileSize = 100 * 1024 * 1024

var simpleEntryRegex = regexp.MustCompile(`^[0-9a-f]{16}_0$`)

type ChromeCachePluginArgs struct {
	Path           *accessors.OSPath `vfilter:"required,field=path,doc=Path to the Chromium cache directory (the directory containing the index/data_N files or the <hash>_0 files)."`
	Accessor       string            `vfilter:"optional,field=accessor,doc=The accessor to use."`
	IncludeContent bool              `vfilter:"optional,field=include_content,doc=If set, the (stream 1) response body is included as bytes in the Content column."`
}

type ChromeCachePlugin struct{}

func (self ChromeCachePlugin) Call(
	ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer utils.RecoverVQL(scope)
		defer vql_subsystem.RegisterMonitor(ctx, "chrome_cache", args)()

		arg := &ChromeCachePluginArgs{}
		err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("chrome_cache: %v", err)
			return
		}

		err = vql_subsystem.CheckAccess(scope, acls.FILESYSTEM_READ)
		if err != nil {
			scope.Log("chrome_cache: %v", err)
			return
		}

		accessor, err := accessors.GetAccessor(arg.Accessor, scope)
		if err != nil {
			scope.Log("chrome_cache: %v", err)
			return
		}

		reader := &cacheDir{
			ctx:      ctx,
			scope:    scope,
			accessor: accessor,
			root:     arg.Path,
		}

		// Detect which cache format is in use. Prefer the blockfile
		// format when an index file with the right magic is present,
		// otherwise fall back to enumerating simple-cache entry files.
		if reader.isBlockFile() {
			self.parseBlockFile(ctx, scope, reader, arg, output_chan)
		} else {
			self.parseSimpleCache(ctx, scope, reader, arg, output_chan)
		}
	}()
	return output_chan
}

func (self ChromeCachePlugin) parseBlockFile(
	ctx context.Context, scope vfilter.Scope,
	reader *cacheDir, arg *ChromeCachePluginArgs,
	output_chan chan vfilter.Row) {

	indexData, err := reader.readFile("index")
	if err != nil {
		scope.Log("chrome_cache: reading index: %v", err)
		return
	}

	addrs, err := chromecache.ParseIndex(indexData)
	if err != nil {
		scope.Log("chrome_cache: %v", err)
		return
	}

	seen := make(map[chromecache.CacheAddr]bool)
	for _, addr := range addrs {
		// Follow the collision chain for this bucket.
		for addr.IsInitialized() && !seen[addr] {
			seen[addr] = true

			entry, err := reader.readEntry(addr)
			if err != nil {
				scope.Log("DEBUG:chrome_cache: entry at 0x%08x: %v", uint32(addr), err)
				break
			}

			row := self.entryToRow(reader, entry, arg)
			select {
			case <-ctx.Done():
				return
			case output_chan <- row:
			}

			addr = entry.Next
		}
	}
}

func (self ChromeCachePlugin) entryToRow(
	reader *cacheDir, entry *chromecache.EntryStore,
	arg *ChromeCachePluginArgs) *ordereddict.Dict {

	key := entry.Key
	if key == "" && entry.LongKey.IsInitialized() {
		keyData, _ := reader.readData(entry.LongKey, int(entry.KeyLen))
		key = string(keyData)
	}

	row := ordereddict.NewDict().
		Set("Key", key).
		Set("URL", cacheKeyToURL(key)).
		Set("EntryID", fmt.Sprintf("%08x", entry.Hash)).
		Set("CreationTime", chromecache.ChromiumTime(entry.CreationTime)).
		Set("ReuseCount", entry.ReuseCount).
		Set("DataSize", entry.DataSize[1])

	// Stream 0 holds the serialized HttpResponseInfo (headers).
	headerData, _ := reader.readData(entry.DataAddr[0], int(entry.DataSize[0]))
	resp := chromecache.ExtractHTTPResponse(headerData)
	if resp != nil {
		row.Set("StatusCode", resp.ResponseCode).
			Set("Headers", resp.Headers)
	} else {
		row.Set("StatusCode", nil).Set("Headers", nil)
	}

	if arg.IncludeContent {
		body, _ := reader.readData(entry.DataAddr[1], int(entry.DataSize[1]))
		row.Set("Content", body)
	}

	return row
}

func (self ChromeCachePlugin) parseSimpleCache(
	ctx context.Context, scope vfilter.Scope,
	reader *cacheDir, arg *ChromeCachePluginArgs,
	output_chan chan vfilter.Row) {

	children, err := reader.accessor.ReadDirWithOSPath(reader.root)
	if err != nil {
		scope.Log("chrome_cache: %v", err)
		return
	}

	found := false
	for _, child := range children {
		if !simpleEntryRegex.MatchString(child.Name()) {
			continue
		}
		found = true

		data, err := reader.readFileOSPath(child.OSPath())
		if err != nil {
			scope.Log("DEBUG:chrome_cache: %v", err)
			continue
		}

		entry, err := chromecache.ParseSimpleFile(data)
		if err != nil {
			scope.Log("DEBUG:chrome_cache: %v: %v", child.Name(), err)
			continue
		}

		// The file stem (the 16 hex digit hash) is a stable per-entry
		// identifier.
		entryID := child.Name()
		if idx := len(entryID) - 2; idx > 0 && entryID[idx:] == "_0" {
			entryID = entryID[:idx]
		}

		row := ordereddict.NewDict().
			Set("Key", entry.Key).
			Set("URL", cacheKeyToURL(entry.Key)).
			Set("EntryID", entryID).
			Set("CreationTime", child.ModTime()).
			Set("DataSize", len(entry.Stream1)).
			Set("OSPath", child.OSPath())

		resp := chromecache.ExtractHTTPResponse(entry.Stream0)
		if resp != nil {
			row.Set("StatusCode", resp.ResponseCode).
				Set("Headers", resp.Headers)
		} else {
			row.Set("StatusCode", nil).Set("Headers", nil)
		}

		if arg.IncludeContent {
			row.Set("Content", entry.Stream1)
		}

		select {
		case <-ctx.Done():
			return
		case output_chan <- row:
		}
	}

	if !found {
		scope.Log("chrome_cache: no recognizable cache entries found in %v",
			reader.root.String())
	}
}

func (self ChromeCachePlugin) Info(
	scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "chrome_cache",
		Doc:      "Parse the Chromium disk cache (both the blockfile and the simple cache formats) as used by Chrome, Edge and Electron applications.",
		ArgType:  type_map.AddType(scope, &ChromeCachePluginArgs{}),
		Metadata: vql.VQLMetadata().Permissions(acls.FILESYSTEM_READ).Build(),
	}
}

// cacheDir provides accessor backed file reads scoped to a single cache
// directory. Block files are read once and cached for the lifetime of
// the query.
type cacheDir struct {
	ctx      context.Context
	scope    vfilter.Scope
	accessor accessors.FileSystemAccessor
	root     *accessors.OSPath

	blockFiles map[string][]byte
}

func (self *cacheDir) isBlockFile() bool {
	data, err := self.readFile("index")
	if err != nil || len(data) < 4 {
		return false
	}
	_, err = chromecache.ParseIndex(data)
	return err == nil
}

func (self *cacheDir) readFile(name string) ([]byte, error) {
	return self.readFileOSPath(self.root.Append(name))
}

func (self *cacheDir) readFileOSPath(path *accessors.OSPath) ([]byte, error) {
	fd, err := self.accessor.OpenWithOSPath(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	return io.ReadAll(io.LimitReader(fd, maxCacheFileSize))
}

// readBlockFile reads and caches a "data_N" block file.
func (self *cacheDir) readBlockFile(name string) ([]byte, error) {
	if self.blockFiles == nil {
		self.blockFiles = make(map[string][]byte)
	}
	if data, pres := self.blockFiles[name]; pres {
		return data, nil
	}
	data, err := self.readFile(name)
	if err != nil {
		return nil, err
	}
	self.blockFiles[name] = data
	return data, nil
}

func (self *cacheDir) readEntry(addr chromecache.CacheAddr) (*chromecache.EntryStore, error) {
	data, err := self.readData(addr, chromecache.EntryStoreSize())
	if err != nil {
		return nil, err
	}
	return chromecache.ParseEntry(data)
}

// readData resolves a CacheAddr to its bytes, reading from either a
// block file or an external f_xxxxxx file. size limits the returned
// slice to the actual stored payload (block files allocate in whole
// block multiples).
func (self *cacheDir) readData(addr chromecache.CacheAddr, size int) ([]byte, error) {
	if !addr.IsInitialized() {
		return nil, nil
	}

	if addr.IsExternal() {
		name := fmt.Sprintf("f_%06x", addr.FileNumber())
		data, err := self.readFile(name)
		if err != nil {
			return nil, err
		}
		if size > 0 && size <= len(data) {
			return data[:size], nil
		}
		return data, nil
	}

	if !addr.IsBlockFile() {
		return nil, fmt.Errorf("chrome_cache: unsupported address type %d", addr.FileType())
	}

	name := fmt.Sprintf("data_%d", addr.FileSelector())
	data, err := self.readBlockFile(name)
	if err != nil {
		return nil, err
	}

	offset := addr.FileOffset()
	length := addr.NumBlocks() * addr.BlockSize()
	if size > 0 && size < length {
		length = size
	}
	if offset < 0 || offset+length > len(data) {
		return nil, fmt.Errorf("chrome_cache: address 0x%08x out of range in %s",
			uint32(addr), name)
	}
	return data[offset : offset+length], nil
}

// cacheKeyToURL extracts the URL from a Chromium cache key. Modern keys
// are prefixed with a NetworkIsolationKey, eg
// "1/0/_dk_https://example.com https://example.com/foo". The actual
// resource URL is the final whitespace separated token.
func cacheKeyToURL(key string) string {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == ' ' {
			return key[i+1:]
		}
	}
	return key
}

func init() {
	vql_subsystem.RegisterPlugin(&ChromeCachePlugin{})
}
