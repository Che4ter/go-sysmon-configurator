package main

import (
	"fmt"
	"log"

	"github.com/Che4ter/go-sysmon-configurator/config"
	"github.com/Che4ter/go-sysmon-configurator/helper"
	"github.com/Che4ter/go-sysmon-configurator/sysmon"
)

var Version = "dev build"

func main() {
	fmt.Println("genconfig " + Version)

	cfgPath, generateRuleIds, removeRuleNames, err := config.ParseFlags()
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	sysmonBaseConfig, err := sysmon.GenerateBaseSysmonConfig(*cfg, Version)
	if err != nil {

		log.Fatal(err)
	}

	sysmonModules, err := sysmon.LoadSysmonModules(cfg.ModulesBasePath, cfg.Modules)
	if err != nil {
		log.Fatal(err)
	}

	sysmonConfig, err := sysmon.AddModulesToConfig(sysmonBaseConfig, sysmonModules, cfg.EventFilter, generateRuleIds, removeRuleNames)
	if err != nil {
		log.Fatal(err)
	}

	err = helper.SaveAsXML(cfg.OutFilename, sysmonConfig)
	if err != nil {
		log.Fatal(err)
	}

	sysmonConfigHash, err := helper.CalcSha256sum(cfg.OutFilename)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Config successfully generated and saved to: " + cfg.OutFilename)
	fmt.Println("SHA256: " + sysmonConfigHash)
}
