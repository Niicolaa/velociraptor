package parsers_test

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/goleveldb/leveldb"
	"www.velocidex.com/golang/velociraptor/accessors"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/acl_managers"
	"www.velocidex.com/golang/velociraptor/vql/parsers"
)

// TestLevelDBIndexedDBPipeline writes a real LevelDB database holding an
// IndexedDB style value (a V8 structured clone blob wrapped in the
// Blink/value-version envelope) and verifies it can be read back through
// the leveldb() plugin and decoded with v8_deserialize().
func TestLevelDBIndexedDBPipeline(t *testing.T) {
	dir := t.TempDir()

	db, err := leveldb.OpenFile(dir, nil)
	require.NoError(t, err)

	// {name:"alice", age:30} as a V8 blob, wrapped the way an IndexedDB
	// object-store record value is stored: <value_version>=1, then the
	// blink version tag 0xFF + version, then the V8 blob (0xFF + ver).
	v8blob := []byte{
		0xFF, 0x0F, 'o',
		0x22, 0x04, 'n', 'a', 'm', 'e',
		0x22, 0x05, 'a', 'l', 'i', 'c', 'e',
		0x22, 0x03, 'a', 'g', 'e',
		'I', 0x3C, // int32 zigzag(30)
		'{', 0x02,
	}
	wrapped := append([]byte{0x01, 0xFF, 0x11}, v8blob...)
	require.NoError(t, db.Put([]byte("recordkey"), wrapped, nil))
	require.NoError(t, db.Close())

	scope := vql_subsystem.MakeScope()
	scope.SetLogger(log.New(os.Stderr, "", 0))
	scope.AppendVars(ordereddict.NewDict().
		Set(vql_subsystem.ACL_MANAGER_VAR, acl_managers.NullACLManager{}))
	defer scope.Close()

	ospath, err := accessors.NewGenericOSPath(dir)
	require.NoError(t, err)

	ctx := context.Background()

	var value string
	for row := range (parsers.LevelDBPlugin{}).Call(ctx, scope,
		ordereddict.NewDict().Set("file", ospath).Set("accessor", "file")) {
		d := row.(*ordereddict.Dict)
		if k, _ := d.Get("Key"); k == "recordkey" {
			v, _ := d.Get("Value")
			value, _ = v.(string)
		}
	}
	require.NotEmpty(t, value, "record not read back from leveldb")

	decoded := (parsers.V8DeserializeFunction{}).Call(ctx, scope,
		ordereddict.NewDict().Set("data", value))

	d, ok := decoded.(*ordereddict.Dict)
	require.True(t, ok, "expected dict, got %T", decoded)

	name, _ := d.Get("name")
	age, _ := d.Get("age")
	assert.Equal(t, "alice", name)
	assert.Equal(t, int64(30), age)
}
