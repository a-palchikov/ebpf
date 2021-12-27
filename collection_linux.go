package ebpf

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// NewCollectionWithOptions creates a Collection from a specification.
//
// Only maps referenced by at least one of the programs are initialized.
func NewCollectionWithOptions(spec *CollectionSpec, opts CollectionOptions) (*Collection, error) {
	maps := make(map[string]*Map)
	for mapName, mapSpec := range spec.Maps {
		m, err := NewMap(mapSpec)
		if err != nil {
			return nil, errors.Wrapf(err, "map %s", mapName)
		}
		maps[mapName] = m
	}

	progs := make(map[string]*Program)
	for progName, origProgSpec := range spec.Programs {
		progSpec := origProgSpec.Copy()
		editor := Edit(&progSpec.Instructions)

		// Rewrite any Symbol which is a valid Map.
		for sym := range editor.ReferenceOffsets {
			m, ok := maps[sym]
			if !ok {
				continue
			}

			// don't overwrite maps already rewritten, users can rewrite programs in the spec themselves
			if err := editor.rewriteMap(sym, m, false); err != nil {
				return nil, errors.Wrapf(err, "program %s", progName)
			}
		}

		prog, err := NewProgramWithOptions(progSpec, opts.Programs)
		if err != nil {
			return nil, errors.Wrapf(err, "program %s", progName)
		}
		progs[progSpec.SectionName] = prog
	}

	return &Collection{
		progs,
		maps,
	}, nil
}

// Pin persits a Collection beyond the lifetime of the process that created it
//
// This requires bpffs to be mounted above fileName. See http://cilium.readthedocs.io/en/doc-1.0/kubernetes/install/#mounting-the-bpf-fs-optional
func (coll *Collection) Pin(dirName string, fileMode os.FileMode) error {
	err := mkdirIfNotExists(dirName, fileMode)
	if err != nil {
		return err
	}
	if len(coll.Maps) > 0 {
		mapPath := filepath.Join(dirName, "maps")
		err = mkdirIfNotExists(mapPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.Maps {
			err := v.Pin(filepath.Join(mapPath, k))
			if err != nil {
				return errors.Wrapf(err, "map %s", k)
			}
		}
	}
	if len(coll.Programs) > 0 {
		progPath := filepath.Join(dirName, "programs")
		err = mkdirIfNotExists(progPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.Programs {
			err = v.Pin(filepath.Join(progPath, k))
			if err != nil {
				return errors.Wrapf(err, "program %s", k)
			}
		}
	}
	return nil
}

func mkdirIfNotExists(dirName string, fileMode os.FileMode) error {
	_, err := os.Stat(dirName)
	if err != nil && os.IsNotExist(err) {
		err = os.Mkdir(dirName, fileMode)
	}
	if err != nil {
		return err
	}
	return nil
}

// LoadPinnedCollection loads a Collection from the pinned directory.
//
// Requires at least Linux 4.13, use LoadPinnedCollectionExplicit on
// earlier versions.
func LoadPinnedCollection(dirName string) (*Collection, error) {
	return loadCollection(
		dirName,
		func(_ string, path string) (*Map, error) {
			return LoadPinnedMap(path)
		},
		func(_ string, path string) (*Program, error) {
			return LoadPinnedProgram(path)
		},
	)
}

// LoadPinnedCollectionExplicit loads a Collection from the pinned directory with explicit parameters.
func LoadPinnedCollectionExplicit(dirName string, maps map[string]*MapABI, progs map[string]*ProgramABI) (*Collection, error) {
	return loadCollection(
		dirName,
		func(name string, path string) (*Map, error) {
			return LoadPinnedMapExplicit(path, maps[name])
		},
		func(name string, path string) (*Program, error) {
			return LoadPinnedProgramExplicit(path, progs[name])
		},
	)
}

func loadCollection(dirName string, loadMap func(string, string) (*Map, error), loadProgram func(string, string) (*Program, error)) (*Collection, error) {
	maps, err := readFileNames(filepath.Join(dirName, "maps"))
	if err != nil {
		return nil, err
	}
	progs, err := readFileNames(filepath.Join(dirName, "programs"))
	if err != nil {
		return nil, err
	}
	bpfColl := &Collection{
		Maps:     make(map[string]*Map),
		Programs: make(map[string]*Program),
	}
	for _, mf := range maps {
		name := filepath.Base(mf)
		m, err := loadMap(name, mf)
		if err != nil {
			return nil, errors.Wrapf(err, "map %s", name)
		}
		bpfColl.Maps[name] = m
	}
	for _, pf := range progs {
		name := filepath.Base(pf)
		prog, err := loadProgram(name, pf)
		if err != nil {
			return nil, errors.Wrapf(err, "program %s", name)
		}
		bpfColl.Programs[name] = prog
	}
	return bpfColl, nil
}

func readFileNames(dirName string) ([]string, error) {
	var fileNames []string
	files, err := ioutil.ReadDir(dirName)
	if err != nil && err != os.ErrNotExist {
		return nil, err
	}
	for _, fi := range files {
		fileNames = append(fileNames, fi.Name())
	}
	return fileNames, nil
}
