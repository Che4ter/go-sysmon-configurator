package config

import (
	"flag"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	SchemaVersion string `yaml:"schemaVersion"`
	Defaults      struct {
		ArchiveDirectory       string   `yaml:"archiveDirectory"`
		CheckRevocation        bool     `yaml:"checkRevocation"`
		CopyOnDeleteExtensions string   `yaml:"copyOnDeleteExtensions"`
		CopyOnDeletePE         bool     `yaml:"copyOnDeletePE"`
		CopyOnDeleteProcesses  string   `yaml:"copyOnDeleteProcesses"`
		CopyOnDeleteSIDs       string   `yaml:"copyOnDeleteSIDs"`
		DNSLookup              bool     `yaml:"dnsLookup"`
		DriverName             string   `yaml:"driverName"`
		HashAlgorithms         []string `yaml:"hashAlgorithms"`
	} `yaml:"defaults"`
	OutFilename     string        `yaml:"outFilename"`
	EventFilter     []EventFilter `yaml:"eventFilter"`
	ModulesBasePath string        `yaml:"modulesBasePath"`
	Modules         []string      `yaml:"modules"`
}

type EventFilter struct {
	EventName string `yaml:"eventName"`
	Include   bool   `yaml:"include"`
	Exclude   bool   `yaml:"exclude"`
}

func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}

	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func ParseFlags() (string, bool, bool, error) {
	var configPath string
	var generateRuleIds bool
	var removeRuleNames bool

	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")
	flag.BoolVar(&generateRuleIds, "genid", false, "replaces rule names with id")
	flag.BoolVar(&removeRuleNames, "rmnames", false, "removes rule names")

	flag.Parse()

	return configPath, generateRuleIds, removeRuleNames, nil
}
