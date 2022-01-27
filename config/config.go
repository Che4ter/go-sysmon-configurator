package config

import (
	"flag"
	"os"
	"strings"

	"github.com/Che4ter/go-sysmon-configurator/sysmon"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Defaults struct {
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
	OutFilename string `yaml:"outFilename"`
	EventFilter struct {
		ProcessCreate struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"ProcessCreate"`
		FileCreateTime struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"FileCreateTime"`
		NetworkConnect struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"NetworkConnect"`
		ProcessTerminate struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"ProcessTerminate"`
		DriverLoad struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"DriverLoad"`
		ImageLoad struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"ImageLoad"`
		CreateRemoteThread struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"CreateRemoteThread"`
		RawAccessRead struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"RawAccessRead"`
		ProcessAccess struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"ProcessAccess"`
		FileCreate struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"FileCreate"`
		RegistryEvent struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"RegistryEvent"`
		FileCreateStreamHash struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"FileCreateStreamHash"`
		PipeEvent struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"PipeEvent"`
		WmiEvent struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"WmiEvent"`
		DNSQuery struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"DnsQuery"`
		FileDelete struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"FileDelete"`
		ClipboardChange struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"ClipboardChange"`
		ProcessTampering struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"ProcessTampering"`
		FileDeleteDetected struct {
			Include bool `yaml:"include"`
			Exclude bool `yaml:"exclude"`
		} `yaml:"FileDeleteDetected"`
	} `yaml:"eventFilter"`
	ModulesBasePath string   `yaml:"modulesBasePath"`
	Modules         []string `yaml:"modules"`
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

func GenerateBaseSysmonConfig(cfg Config, schemaVersion float32) (*sysmon.Sysmon, error) {
	var sysmonBaseConfig sysmon.Sysmon
	sysmonBaseConfig.SchemaversionAttr = schemaVersion
	sysmonBaseConfig.ArchiveDirectory = cfg.Defaults.ArchiveDirectory
	sysmonBaseConfig.CheckRevocation = cfg.Defaults.CheckRevocation
	sysmonBaseConfig.CopyOnDeleteExtensions = cfg.Defaults.CopyOnDeleteExtensions
	sysmonBaseConfig.CopyOnDeletePE = cfg.Defaults.CopyOnDeletePE
	sysmonBaseConfig.CopyOnDeleteProcesses = cfg.Defaults.CopyOnDeleteProcesses
	sysmonBaseConfig.CopyOnDeleteSIDs = cfg.Defaults.CopyOnDeleteSIDs
	sysmonBaseConfig.DnsLookup = cfg.Defaults.DNSLookup
	sysmonBaseConfig.DriverName = cfg.Defaults.DriverName
	sysmonBaseConfig.HashAlgorithms = strings.Join(cfg.Defaults.HashAlgorithms, ", ")

	sysmonBaseConfig.EventFiltering.RuleGroup = []*sysmon.RuleGroup{}

	if cfg.EventFilter.ProcessCreate.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ProcessCreate: append([]*sysmon.ProcessCreate{}, &sysmon.ProcessCreate{
					OnmatchAttr: "include",
					Rules:       []*sysmon.ProcessCreateRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ProcessCreate.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ProcessCreate: append([]*sysmon.ProcessCreate{}, &sysmon.ProcessCreate{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.ProcessCreateRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileCreateTime.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileCreateTime: append([]*sysmon.FileCreateTime{}, &sysmon.FileCreateTime{
					OnmatchAttr: "include",
					Rules:       []*sysmon.FileCreateTimeRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileCreateTime.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileCreateTime: append([]*sysmon.FileCreateTime{}, &sysmon.FileCreateTime{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.FileCreateTimeRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.NetworkConnect.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				NetworkConnect: append([]*sysmon.NetworkConnect{}, &sysmon.NetworkConnect{
					OnmatchAttr: "include",
					Rules:       []*sysmon.NetworkConnectRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.NetworkConnect.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				NetworkConnect: append([]*sysmon.NetworkConnect{}, &sysmon.NetworkConnect{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.NetworkConnectRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ProcessTerminate.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ProcessTerminate: append([]*sysmon.ProcessTerminate{}, &sysmon.ProcessTerminate{
					OnmatchAttr: "include",
					Rules:       []*sysmon.ProcessTerminateRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ProcessTerminate.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ProcessTerminate: append([]*sysmon.ProcessTerminate{}, &sysmon.ProcessTerminate{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.ProcessTerminateRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.DriverLoad.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				DriverLoad: append([]*sysmon.DriverLoad{}, &sysmon.DriverLoad{
					OnmatchAttr: "include",
					Rules:       []*sysmon.DriverLoadRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.DriverLoad.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				DriverLoad: append([]*sysmon.DriverLoad{}, &sysmon.DriverLoad{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.DriverLoadRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ImageLoad.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ImageLoad: append([]*sysmon.ImageLoad{}, &sysmon.ImageLoad{
					OnmatchAttr: "include",
					Rules:       []*sysmon.ImageLoadRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ImageLoad.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ImageLoad: append([]*sysmon.ImageLoad{}, &sysmon.ImageLoad{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.ImageLoadRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.CreateRemoteThread.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				CreateRemoteThread: append([]*sysmon.CreateRemoteThread{}, &sysmon.CreateRemoteThread{
					OnmatchAttr: "include",
					Rules:       []*sysmon.CreateRemoteThreadRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.CreateRemoteThread.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				CreateRemoteThread: append([]*sysmon.CreateRemoteThread{}, &sysmon.CreateRemoteThread{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.CreateRemoteThreadRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.RawAccessRead.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				RawAccessRead: append([]*sysmon.RawAccessRead{}, &sysmon.RawAccessRead{
					OnmatchAttr: "include",
					Rules:       []*sysmon.RawAccessReadRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.RawAccessRead.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				RawAccessRead: append([]*sysmon.RawAccessRead{}, &sysmon.RawAccessRead{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.RawAccessReadRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ProcessAccess.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ProcessAccess: append([]*sysmon.ProcessAccess{}, &sysmon.ProcessAccess{
					OnmatchAttr: "include",
					Rules:       []*sysmon.ProcessAccessRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ProcessAccess.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ProcessAccess: append([]*sysmon.ProcessAccess{}, &sysmon.ProcessAccess{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.ProcessAccessRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileCreate.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileCreate: append([]*sysmon.FileCreate{}, &sysmon.FileCreate{
					OnmatchAttr: "include",
					Rules:       []*sysmon.FileCreateRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileCreate.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileCreate: append([]*sysmon.FileCreate{}, &sysmon.FileCreate{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.FileCreateRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.RegistryEvent.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				RegistryEvent: append([]*sysmon.RegistryEvent{}, &sysmon.RegistryEvent{
					OnmatchAttr: "include",
					Rules:       []*sysmon.RegistryEventRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.RegistryEvent.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				RegistryEvent: append([]*sysmon.RegistryEvent{}, &sysmon.RegistryEvent{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.RegistryEventRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileCreateStreamHash.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileCreateStreamHash: append([]*sysmon.FileCreateStreamHash{}, &sysmon.FileCreateStreamHash{
					OnmatchAttr: "include",
					Rules:       []*sysmon.FileCreateStreamHashRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileCreateStreamHash.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileCreateStreamHash: append([]*sysmon.FileCreateStreamHash{}, &sysmon.FileCreateStreamHash{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.FileCreateStreamHashRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.PipeEvent.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				PipeEvent: append([]*sysmon.PipeEvent{}, &sysmon.PipeEvent{
					OnmatchAttr: "include",
					Rules:       []*sysmon.PipeEventRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.PipeEvent.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				PipeEvent: append([]*sysmon.PipeEvent{}, &sysmon.PipeEvent{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.PipeEventRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.WmiEvent.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				WmiEvent: append([]*sysmon.WmiEvent{}, &sysmon.WmiEvent{
					OnmatchAttr: "include",
					Rules:       []*sysmon.WmiEventRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.WmiEvent.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				WmiEvent: append([]*sysmon.WmiEvent{}, &sysmon.WmiEvent{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.WmiEventRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.DNSQuery.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				DnsQuery: append([]*sysmon.DnsQuery{}, &sysmon.DnsQuery{
					OnmatchAttr: "include",
					Rules:       []*sysmon.DnsQueryRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.DNSQuery.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				DnsQuery: append([]*sysmon.DnsQuery{}, &sysmon.DnsQuery{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.DnsQueryRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileDelete.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileDelete: append([]*sysmon.FileDelete{}, &sysmon.FileDelete{
					OnmatchAttr: "include",
					Rules:       []*sysmon.FileDeleteRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileDelete.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileDelete: append([]*sysmon.FileDelete{}, &sysmon.FileDelete{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.FileDeleteRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ClipboardChange.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ClipboardChange: append([]*sysmon.ClipboardChange{}, &sysmon.ClipboardChange{
					OnmatchAttr: "include",
					Rules:       []*sysmon.ClipboardChangeRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ClipboardChange.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ClipboardChange: append([]*sysmon.ClipboardChange{}, &sysmon.ClipboardChange{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.ClipboardChangeRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ProcessTampering.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ProcessTampering: append([]*sysmon.ProcessTampering{}, &sysmon.ProcessTampering{
					OnmatchAttr: "include",
					Rules:       []*sysmon.ProcessTamperingRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.ProcessTampering.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				ProcessTampering: append([]*sysmon.ProcessTampering{}, &sysmon.ProcessTampering{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.ProcessTamperingRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileDeleteDetected.Include == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileDeleteDetected: append([]*sysmon.FileDeleteDetected{}, &sysmon.FileDeleteDetected{
					OnmatchAttr: "include",
					Rules:       []*sysmon.FileDeleteDetectedRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	if cfg.EventFilter.FileDeleteDetected.Exclude == true {
		sysmonBaseConfig.EventFiltering.RuleGroup = append(sysmonBaseConfig.EventFiltering.RuleGroup, &sysmon.RuleGroup{
			EventFilteringRules: sysmon.EventFilteringRules{
				FileDeleteDetected: append([]*sysmon.FileDeleteDetected{}, &sysmon.FileDeleteDetected{
					OnmatchAttr: "exclude",
					Rules:       []*sysmon.FileDeleteDetectedRule{},
				}),
			},
			GroupRelationAttr: "or",
		})
	}

	return &sysmonBaseConfig, nil
}
