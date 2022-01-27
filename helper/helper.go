package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"io/ioutil"
	"os"
	"reflect"
)

type FlattenStruct struct {
	Value reflect.Value
	Name  string
}

func FlattenStructs(iface interface{}) []FlattenStruct {
	fields := make([]FlattenStruct, 0)
	ifv := reflect.ValueOf(iface)
	ift := reflect.TypeOf(iface)

	for i := 0; i < ift.NumField(); i++ {
		v := ifv.Field(i)

		switch v.Kind() {
		case reflect.Struct:
			fields = append(fields, FlattenStructs(v.Interface())...)
		default:
			fields = append(fields, FlattenStruct{v, ift.Field(i).Name})
		}
	}

	return fields
}

func SaveAsXML(path string, content interface{}) error {
	file, err := xml.MarshalIndent(content, "", " ")

	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, file, 0644)
	if err != nil {
		return err
	}

	return nil
}

func CalcSha256sum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
