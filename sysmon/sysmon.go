package sysmon

import (
	"encoding/xml"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"strconv"

	"github.com/Che4ter/go-sysmon-configurator/helper"
)

func LoadSysmonModules(basePath string, modulesPath []string) ([]*Sysmon, error) {
	sysmonModules := []*Sysmon{}

	for _, modulesPath := range modulesPath {
		xmlFile, err := os.Open(basePath + modulesPath)
		if err != nil {
			return nil, err
		}

		defer xmlFile.Close()

		byteValue, _ := ioutil.ReadAll(xmlFile)

		var sysmonModule Sysmon
		xml.Unmarshal(byteValue, &sysmonModule)

		sysmonModules = append(sysmonModules, &sysmonModule)
	}

	return sysmonModules, nil
}

func MergeModulesWithBaseConfig(sysmonBaseConfig *Sysmon, sysmonModules []*Sysmon) error {
	for _, sysmonModule := range sysmonModules {
		if sysmonModule.EventFiltering.RuleGroup != nil { //check if Rule Group exists in source config
			for _, sourceRulegroup := range sysmonModule.EventFiltering.RuleGroup { //for each rule group in source config
				sourceGroupRelation := sourceRulegroup.GroupRelationAttr          //get group relation (and/or) of source rule group
				sourceFlattenRuleGroup := helper.FlattenStructs(*sourceRulegroup) //flatten the source rule group -> Gives Event Type Rules (ProcessCreate, FileCreatTime...)
				for _, sourceEventType := range sourceFlattenRuleGroup {          //for each event type in source rule group
					if sourceEventType.Value.Kind() == reflect.Slice { //only use slices and not attributes
						for i := 0; i < sourceEventType.Value.Len(); i++ { //loop rules per event type eg. single processcreate block
							sourceConditionStruct := sourceEventType.Value.Index(i).Elem().Interface()
							sourceConditionsFlatten := helper.FlattenStructs(sourceConditionStruct)               //flatten event type structs to get all conditions
							sourceOnMatchAttr := sourceEventType.Value.Index(i).Elem().FieldByName("OnmatchAttr") //include/exclude

							//match with targetconfig, only merge if a rule block with the same condition exists in the target (include/exclude)
							for _, targetRulegroup := range sysmonBaseConfig.EventFiltering.RuleGroup {
								if targetRulegroup.GroupRelationAttr == sourceGroupRelation {
									targetFlattenRuleGroup := helper.FlattenStructs(*targetRulegroup)
									for _, targetEventType := range targetFlattenRuleGroup { //for each event type in target rule group
										if targetEventType.Value.Type() == sourceEventType.Value.Type() { //search for the same event type block
											for j := 0; j < targetEventType.Value.Len(); j++ {
												targetOnMatchAttr := targetEventType.Value.Index(j).Elem().FieldByName("OnmatchAttr")

												if targetOnMatchAttr.String() == sourceOnMatchAttr.String() { //check if the onmatch type (exclude/include) is the same
													for _, sourceCondition := range sourceConditionsFlatten { //for each condition in the source config
														if sourceCondition.Value.Kind() == reflect.Slice { //filter out attributes
															targetCondition := targetEventType.Value.Index(j).Elem().FieldByName(sourceCondition.Name) //get target condition slice
															targetCondition.Set(reflect.AppendSlice(targetCondition, sourceCondition.Value))           //append target condition slice
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

func RemoveRuleNames(sysmonBaseConfig *Sysmon) error {
	content, err := xml.MarshalIndent(sysmonBaseConfig, "", " ")
	if err != nil {
		return err
	}

	s := string(content)
	nameRegex := regexp.MustCompile("name=\"(.*?)\"")
	s = nameRegex.ReplaceAllString(s, "")

	var modifiedSysmon Sysmon
	err = xml.Unmarshal([]byte(s), &modifiedSysmon)
	if err != nil {
		return err
	}

	*sysmonBaseConfig = modifiedSysmon

	return nil
}

func ReplaceRuleNamesWithID(sysmonBaseConfig *Sysmon) error {
	content, err := xml.MarshalIndent(sysmonBaseConfig, "", " ")
	if err != nil {
		return err
	}

	s := string(content)
	nameRegex := regexp.MustCompile("name=\"(.*?)\"")
	s = nameRegex.ReplaceAllString(s, "")

	idRegex := regexp.MustCompile("condition=\"")
	ruleId := 0
	s = idRegex.ReplaceAllStringFunc(s, func(m string) string {
		result := "name=\"" + strconv.Itoa(ruleId) + "\" condition=\""
		ruleId++
		return result
	})

	var modifiedSysmon Sysmon
	err = xml.Unmarshal([]byte(s), &modifiedSysmon)
	if err != nil {
		return err
	}

	*sysmonBaseConfig = modifiedSysmon

	return nil
}

// GenericStringRule is This type is applied to a Sysmon rule element where there are no constraints on the value.
type GenericStringRule struct {
	NameAttr      string `xml:"name,attr,omitempty"`
	ConditionAttr string `xml:"condition,attr,omitempty"`
	Value         string `xml:",chardata"`
}

// UInt32Rule is This type is applied to a Sysmon rule element where there are no constraints on the value.
type UInt32Rule struct {
	NameAttr      string `xml:"name,attr,omitempty"`
	ConditionAttr string `xml:"condition,attr,omitempty"`
	Value         uint32 `xml:",chardata"`
}

// UInt16Rule is This type is applied to a Sysmon rule element where the value is expected to be an unsigned short.
type UInt16Rule struct {
	NameAttr      string `xml:"name,attr,omitempty"`
	ConditionAttr string `xml:"condition,attr,omitempty"`
	Value         uint16 `xml:",chardata"`
}

// GuidRule is This type is applied to a Sysmon rule element where the value is expected to be a GUID.
type GuidRule struct {
	NameAttr      string `xml:"name,attr,omitempty"`
	ConditionAttr string `xml:"condition,attr,omitempty"`
	Value         string `xml:",chardata"`
}

// HexRule is This type is applied to a Sysmon rule element where the value is expected to be a hexadecimal value.
type HexRule struct {
	NameAttr      string `xml:"name,attr,omitempty"`
	ConditionAttr string `xml:"condition,attr,omitempty"`
	Value         []byte `xml:",chardata"`
}

// BooleanRule is This type is applied to a Sysmon rule element where the value is expected to be either "true" or "false".
type BooleanRule struct {
	NameAttr      string `xml:"name,attr,omitempty"`
	ConditionAttr string `xml:"condition,attr,omitempty"`
	Value         bool   `xml:",chardata"`
}

// ProcessCreate - Event ID 1
type ProcessCreate struct {
	OnmatchAttr string               `xml:"onmatch,attr"`
	Rules       []*ProcessCreateRule `xml:"Rule,omitempty"`
	ProcessCreateFields
}

type ProcessCreateFields struct {
	UtcTime           []*GenericStringRule `xml:"UtcTime,omitempty"`
	ProcessGuid       []*GuidRule          `xml:"ProcessGuid,omitempty"`
	ProcessId         []*UInt32Rule        `xml:"ProcessId,omitempty"`
	Image             []*GenericStringRule `xml:"Image,omitempty"`
	FileVersion       []*GenericStringRule `xml:"FileVersion,omitempty"`
	Description       []*GenericStringRule `xml:"Description,omitempty"`
	Product           []*GenericStringRule `xml:"Product,omitempty"`
	Company           []*GenericStringRule `xml:"Company,omitempty"`
	OriginalFileName  []*GenericStringRule `xml:"OriginalFileName,omitempty"`
	CommandLine       []*GenericStringRule `xml:"CommandLine,omitempty"`
	CurrentDirectory  []*GenericStringRule `xml:"CurrentDirectory,omitempty"`
	User              []*GenericStringRule `xml:"User,omitempty"`
	LogonGuid         []*GuidRule          `xml:"LogonGuid,omitempty"`
	LogonId           []*HexRule           `xml:"LogonId,omitempty"`
	TerminalSessionId []*UInt32Rule        `xml:"TerminalSessionId,omitempty"`
	IntegrityLevel    []*GenericStringRule `xml:"IntegrityLevel,omitempty"`
	Hashes            []*GenericStringRule `xml:"Hashes,omitempty"`
	ParentProcessGuid []*GuidRule          `xml:"ParentProcessGuid,omitempty"`
	ParentProcessId   []*UInt32Rule        `xml:"ParentProcessId,omitempty"`
	ParentImage       []*GenericStringRule `xml:"ParentImage,omitempty"`
	ParentCommandLine []*GenericStringRule `xml:"ParentCommandLine,omitempty"`
	ParentUser        []*GenericStringRule `xml:"ParentUser,omitempty"`
}

type ProcessCreateRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	ProcessCreateFields
}

// FileCreateTime - Event ID 2
type FileCreateTime struct {
	OnmatchAttr string                `xml:"onmatch,attr"`
	Rules       []*FileCreateTimeRule `xml:"Rule,omitempty"`
	FileCreateTimeFields
}

type FileCreateTimeFields struct {
	UtcTime                 []*GenericStringRule `xml:"UtcTime,omitempty"`
	ProcessGuid             []*GuidRule          `xml:"ProcessGuid,omitempty"`
	ProcessId               []*UInt32Rule        `xml:"ProcessId,omitempty"`
	Image                   []*GenericStringRule `xml:"Image,omitempty"`
	TargetFilename          []*GenericStringRule `xml:"TargetFilename,omitempty"`
	CreationUtcTime         []*GenericStringRule `xml:"CreationUtcTime,omitempty"`
	PreviousCreationUtcTime []*GenericStringRule `xml:"PreviousCreationUtcTime,omitempty"`
	User                    []*GenericStringRule `xml:"User,omitempty"`
}

type FileCreateTimeRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	FileCreateTimeFields
}

// NetworkConnect - Event ID 3
type NetworkConnect struct {
	OnmatchAttr string                `xml:"onmatch,attr"`
	Rules       []*NetworkConnectRule `xml:"Rule"`
	NetworkConnectFields
}

type NetworkConnectFields struct {
	UtcTime             []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid         []*GuidRule          `xml:"ProcessGuid"`
	ProcessId           []*UInt32Rule        `xml:"ProcessId"`
	Image               []*GenericStringRule `xml:"Image"`
	User                []*GenericStringRule `xml:"User"`
	Protocol            []*GenericStringRule `xml:"Protocol"`
	Initiated           []*BooleanRule       `xml:"Initiated"`
	SourceIsIpv6        []*BooleanRule       `xml:"SourceIsIpv6"`
	SourceIp            []*GenericStringRule `xml:"SourceIp"`
	SourceHostname      []*GenericStringRule `xml:"SourceHostname"`
	SourcePort          []*UInt16Rule        `xml:"SourcePort"`
	SourcePortName      []*GenericStringRule `xml:"SourcePortName"`
	DestinationIsIpv6   []*BooleanRule       `xml:"DestinationIsIpv6"`
	DestinationIp       []*GenericStringRule `xml:"DestinationIp"`
	DestinationHostname []*GenericStringRule `xml:"DestinationHostname"`
	DestinationPort     []*UInt16Rule        `xml:"DestinationPort"`
	DestinationPortName []*GenericStringRule `xml:"DestinationPortName"`
}

type NetworkConnectRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	NetworkConnectFields
}

// ProcessTerminate - Event ID 5
type ProcessTerminate struct {
	OnmatchAttr string                  `xml:"onmatch,attr"`
	Rules       []*ProcessTerminateRule `xml:"Rule"`
	ProcessTerminateFields
}

type ProcessTerminateFields struct {
	UtcTime     []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid []*GuidRule          `xml:"ProcessGuid"`
	ProcessId   []*UInt32Rule        `xml:"ProcessId"`
	Image       []*GenericStringRule `xml:"Image"`
	User        []*GenericStringRule `xml:"User"`
}

type ProcessTerminateRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	ProcessTerminateFields
}

// DriverLoad- Event ID 5
type DriverLoad struct {
	OnmatchAttr string            `xml:"onmatch,attr"`
	Rules       []*DriverLoadRule `xml:"Rule"`
	DriverLoadFields
}

type DriverLoadFields struct {
	UtcTime         []*GenericStringRule `xml:"UtcTime"`
	ImageLoaded     []*GenericStringRule `xml:"ImageLoaded"`
	Hashes          []*GenericStringRule `xml:"Hashes"`
	Signed          []*BooleanRule       `xml:"Signed"`
	Signature       []*GenericStringRule `xml:"Signature"`
	SignatureStatus []*GenericStringRule `xml:"SignatureStatus"`
}

type DriverLoadRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	DriverLoadFields
}

// ImageLoad - Event ID 7
type ImageLoad struct {
	OnmatchAttr string           `xml:"onmatch,attr"`
	Rules       []*ImageLoadRule `xml:"Rule"`
	ImageLoadFields
}

type ImageLoadFields struct {
	UtcTime          []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid      []*GuidRule          `xml:"ProcessGuid"`
	ProcessId        []*UInt32Rule        `xml:"ProcessId"`
	Image            []*GenericStringRule `xml:"Image"`
	ImageLoaded      []*GenericStringRule `xml:"ImageLoaded"`
	FileVersion      []*GenericStringRule `xml:"FileVersion"`
	Description      []*GenericStringRule `xml:"Description"`
	Product          []*GenericStringRule `xml:"Product"`
	Company          []*GenericStringRule `xml:"Company"`
	OriginalFileName []*GenericStringRule `xml:"OriginalFileName"`
	Hashes           []*GenericStringRule `xml:"Hashes"`
	Signed           []*BooleanRule       `xml:"Signed"`
	Signature        []*GenericStringRule `xml:"Signature"`
	SignatureStatus  []*GenericStringRule `xml:"SignatureStatus"`
	User             []*GenericStringRule `xml:"User"`
}

type ImageLoadRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	ImageLoadFields
}

// CreateRemoteThread - Event ID 8
type CreateRemoteThread struct {
	OnmatchAttr string                    `xml:"onmatch,attr"`
	Rules       []*CreateRemoteThreadRule `xml:"Rule"`
	CreateRemoteThreadFields
}

type CreateRemoteThreadFields struct {
	UtcTime           []*GenericStringRule `xml:"UtcTime"`
	SourceProcessGuid []*GuidRule          `xml:"SourceProcessGuid"`
	SourceProcessId   []*UInt32Rule        `xml:"SourceProcessId"`
	SourceImage       []*GenericStringRule `xml:"SourceImage"`
	TargetProcessGuid []*GuidRule          `xml:"TargetProcessGuid"`
	TargetProcessId   []*UInt32Rule        `xml:"TargetProcessId"`
	TargetImage       []*GenericStringRule `xml:"TargetImage"`
	NewThreadId       []*UInt32Rule        `xml:"NewThreadId"`
	StartAddress      []*HexRule           `xml:"StartAddress"`
	StartModule       []*GenericStringRule `xml:"StartModule"`
	StartFunction     []*GenericStringRule `xml:"StartFunction"`
	SourceUser        []*GenericStringRule `xml:"SourceUser"`
	TargetUser        []*GenericStringRule `xml:"TargetUser"`
}

type CreateRemoteThreadRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	CreateRemoteThreadFields
}

// RawAccessRead - Event ID 9
type RawAccessRead struct {
	OnmatchAttr string               `xml:"onmatch,attr"`
	Rules       []*RawAccessReadRule `xml:"Rule"`
	RawAccessReadFields
}

type RawAccessReadFields struct {
	UtcTime     []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid []*GuidRule          `xml:"ProcessGuid"`
	ProcessId   []*UInt32Rule        `xml:"ProcessId"`
	Image       []*GenericStringRule `xml:"Image"`
	Device      []*GenericStringRule `xml:"Device"`
	User        []*GenericStringRule `xml:"User"`
}

type RawAccessReadRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	RawAccessReadFields
}

// ProcessAccess - Event ID 10
type ProcessAccess struct {
	OnmatchAttr string               `xml:"onmatch,attr"`
	Rules       []*ProcessAccessRule `xml:"Rule"`
	ProcessAccessFields
}

type ProcessAccessFields struct {
	UtcTime           []*GenericStringRule `xml:"UtcTime"`
	SourceProcessGUID []*GuidRule          `xml:"SourceProcessGUID"`
	SourceProcessId   []*UInt32Rule        `xml:"SourceProcessId"`
	SourceThreadId    []*UInt32Rule        `xml:"SourceThreadId"`
	SourceImage       []*GenericStringRule `xml:"SourceImage"`
	TargetProcessGUID []*GuidRule          `xml:"TargetProcessGUID"`
	TargetProcessId   []*UInt32Rule        `xml:"TargetProcessId"`
	TargetImage       []*GenericStringRule `xml:"TargetImage"`
	GrantedAccess     []*HexRule           `xml:"GrantedAccess"`
	CallTrace         []*GenericStringRule `xml:"CallTrace"`
	SourceUser        []*GenericStringRule `xml:"SourceUser"`
	TargetUser        []*GenericStringRule `xml:"TargetUser"`
}

type ProcessAccessRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	ProcessAccessFields
}

// FileCreate - Event ID 11
type FileCreate struct {
	OnmatchAttr string            `xml:"onmatch,attr"`
	Rules       []*FileCreateRule `xml:"Rule"`
	FileCreateFields
}

type FileCreateFields struct {
	UtcTime         []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid     []*GuidRule          `xml:"ProcessGuid"`
	ProcessId       []*UInt32Rule        `xml:"ProcessId"`
	Image           []*GenericStringRule `xml:"Image"`
	TargetFilename  []*GenericStringRule `xml:"TargetFilename"`
	CreationUtcTime []*GenericStringRule `xml:"CreationUtcTime"`
	User            []*GenericStringRule `xml:"User"`
}

type FileCreateRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	FileCreateFields
}

// RegistryEvent - Event ID 12, 13, 14
type RegistryEvent struct {
	OnmatchAttr string               `xml:"onmatch,attr"`
	Rules       []*RegistryEventRule `xml:"Rule"`
	RegistryEventFields
}

type RegistryEventFields struct {
	EventType    []*GenericStringRule `xml:"EventType"`
	UtcTime      []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid  []*GuidRule          `xml:"ProcessGuid"`
	ProcessId    []*UInt32Rule        `xml:"ProcessId"`
	Image        []*GenericStringRule `xml:"Image"`
	TargetObject []*GenericStringRule `xml:"TargetObject"`
	Details      []*GenericStringRule `xml:"Details"`
	NewName      []*GenericStringRule `xml:"NewName"`
	User         []*GenericStringRule `xml:"User"`
}

type RegistryEventRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	RegistryEventFields
}

// FileCreateStreamHash - Event ID 15
type FileCreateStreamHash struct {
	OnmatchAttr string                      `xml:"onmatch,attr"`
	Rules       []*FileCreateStreamHashRule `xml:"Rule"`
	FileCreateStreamHashFields
}

type FileCreateStreamHashFields struct {
	UtcTime         []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid     []*GuidRule          `xml:"ProcessGuid"`
	ProcessId       []*UInt32Rule        `xml:"ProcessId"`
	Image           []*GenericStringRule `xml:"Image"`
	TargetFilename  []*GenericStringRule `xml:"TargetFilename"`
	CreationUtcTime []*GenericStringRule `xml:"CreationUtcTime"`
	Hash            []*GenericStringRule `xml:"Hash"`
	Contents        []*GenericStringRule `xml:"Contents"`
	User            []*GenericStringRule `xml:"User"`
}

type FileCreateStreamHashRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	FileCreateStreamHashFields
}

// PipeEvent - Event ID 17, 18
type PipeEvent struct {
	OnmatchAttr string           `xml:"onmatch,attr"`
	Rules       []*PipeEventRule `xml:"Rule"`
	PipeEventFields
}

type PipeEventFields struct {
	EventType   []*GenericStringRule `xml:"EventType"`
	UtcTime     []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid []*GuidRule          `xml:"ProcessGuid"`
	ProcessId   []*UInt32Rule        `xml:"ProcessId"`
	PipeName    []*GenericStringRule `xml:"PipeName"`
	Image       []*GenericStringRule `xml:"Image"`
	User        []*GenericStringRule `xml:"User"`
}

type PipeEventRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	PipeEventFields
}

// WmiEvent - Event ID 19, 20, 21
type WmiEvent struct {
	OnmatchAttr string          `xml:"onmatch,attr"`
	Rules       []*WmiEventRule `xml:"Rule"`
	WmiEventFields
}

type WmiEventFields struct {
	EventType      []*GenericStringRule `xml:"EventType"`
	UtcTime        []*GenericStringRule `xml:"UtcTime"`
	Operation      []*GenericStringRule `xml:"Operation"`
	User           []*GenericStringRule `xml:"User"`
	EventNamespace []*GenericStringRule `xml:"EventNamespace"`
	Name           []*GenericStringRule `xml:"Name"`
	Query          []*GenericStringRule `xml:"Query"`
	Type           []*GenericStringRule `xml:"Type"`
	Destination    []*GenericStringRule `xml:"Destination"`
	Consumer       []*GenericStringRule `xml:"Consumer"`
	Filter         []*GenericStringRule `xml:"Filter"`
}

type WmiEventRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	WmiEventFields
}

// DNS Query - Event ID 22
type DnsQuery struct {
	OnmatchAttr string          `xml:"onmatch,attr"`
	Rules       []*DnsQueryRule `xml:"Rule"`
	DnsQueryFields
}

type DnsQueryFields struct {
	UtcTime      []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid  []*GuidRule          `xml:"ProcessGuid"`
	ProcessId    []*UInt32Rule        `xml:"ProcessId"`
	QueryName    []*GenericStringRule `xml:"QueryName"`
	QueryStatus  []*GenericStringRule `xml:"QueryStatus"`
	QueryResults []*GenericStringRule `xml:"QueryResults"`
	Image        []*GenericStringRule `xml:"Image"`
	User         []*GenericStringRule `xml:"User"`
}

type DnsQueryRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	DnsQueryFields
}

// File Delete - Event ID 23
type FileDelete struct {
	OnmatchAttr string            `xml:"onmatch,attr"`
	Rules       []*FileDeleteRule `xml:"Rule"`
	FileDeleteFields
}

type FileDeleteFields struct {
	UtcTime        []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid    []*GuidRule          `xml:"ProcessGuid"`
	ProcessId      []*UInt32Rule        `xml:"ProcessId"`
	User           []*GenericStringRule `xml:"User"`
	Image          []*GenericStringRule `xml:"Image"`
	TargetFileName []*GenericStringRule `xml:"TargetFileName"`
	Hashes         []*GenericStringRule `xml:"Hashes"`
	IsExecutable   []*BooleanRule       `xml:"IsExecutable"`
	Archived       []*GenericStringRule `xml:"Archived"`
}

type FileDeleteRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	FileDeleteFields
}

// Clipboard changed - Event ID 24
type ClipboardChange struct {
	OnmatchAttr string                 `xml:"onmatch,attr"`
	Rules       []*ClipboardChangeRule `xml:"Rule"`
	ClipboardChangeRule
}

type ClipboardChangeFields struct {
	UtcTime     []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid []*GuidRule          `xml:"ProcessGuid"`
	ProcessId   []*UInt32Rule        `xml:"ProcessId"`
	Image       []*GenericStringRule `xml:"Image"`
	Session     []*GenericStringRule `xml:"Session"`
	ClientInfo  []*GenericStringRule `xml:"ClientInfo"`
	Hashes      []*GenericStringRule `xml:"Hashes"`
	Archived    []*GenericStringRule `xml:"Archived"`
	User        []*GenericStringRule `xml:"User"`
}

type ClipboardChangeRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	ClipboardChangeFields
}

// Process Tampering - Event ID 25
type ProcessTampering struct {
	OnmatchAttr string                  `xml:"onmatch,attr"`
	Rules       []*ProcessTamperingRule `xml:"Rule"`
	ProcessTamperingFields
}

type ProcessTamperingFields struct {
	UtcTime     []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid []*GuidRule          `xml:"ProcessGuid"`
	ProcessId   []*UInt32Rule        `xml:"ProcessId"`
	Image       []*GenericStringRule `xml:"Image"`
	Type        []*GenericStringRule `xml:"Type"`
	User        []*GenericStringRule `xml:"User"`
}

type ProcessTamperingRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	ProcessTamperingFields
}

// File Delete logged - Event ID 26
type FileDeleteDetected struct {
	OnmatchAttr string                    `xml:"onmatch,attr"`
	Rules       []*FileDeleteDetectedRule `xml:"Rule"`
	FileDeleteDetectedRule
}

type FileDeleteDetectedFields struct {
	UtcTime        []*GenericStringRule `xml:"UtcTime"`
	ProcessGuid    []*GuidRule          `xml:"ProcessGuid"`
	ProcessId      []*UInt32Rule        `xml:"ProcessId"`
	TargetFilename []*GenericStringRule `xml:"TargetFilename"`
	Hashes         []*GenericStringRule `xml:"Hashes"`
	Image          []*GenericStringRule `xml:"Image"`
	User           []*GenericStringRule `xml:"User"`
	IsExecutable   []*BooleanRule       `xml:"IsExecutable"`
}

type FileDeleteDetectedRule struct {
	GroupRelationAttr string `xml:"groupRelation,attr"`
	NameAttr          string `xml:"name,attr,omitempty"`
	FileDeleteDetectedFields
}

// EventFiltering ...
type EventFiltering struct {
	*EventFilteringRules
	RuleGroup []*RuleGroup `xml:"RuleGroup,omitempty"`
}

type EventFilteringRules struct {
	ProcessCreate        []*ProcessCreate        `xml:"ProcessCreate,omitempty"`
	FileCreateTime       []*FileCreateTime       `xml:"FileCreateTime,omitempty"`
	NetworkConnect       []*NetworkConnect       `xml:"NetworkConnect,omitempty"`
	ProcessTerminate     []*ProcessTerminate     `xml:"ProcessTerminate,omitempty"`
	DriverLoad           []*DriverLoad           `xml:"DriverLoad,omitempty"`
	ImageLoad            []*ImageLoad            `xml:"ImageLoad,omitempty"`
	CreateRemoteThread   []*CreateRemoteThread   `xml:"CreateRemoteThread,omitempty"`
	RawAccessRead        []*RawAccessRead        `xml:"RawAccessRead,omitempty"`
	ProcessAccess        []*ProcessAccess        `xml:"ProcessAccess,omitempty"`
	FileCreate           []*FileCreate           `xml:"FileCreate,omitempty"`
	RegistryEvent        []*RegistryEvent        `xml:"RegistryEvent,omitempty"`
	FileCreateStreamHash []*FileCreateStreamHash `xml:"FileCreateStreamHash,omitempty"`
	PipeEvent            []*PipeEvent            `xml:"PipeEvent,omitempty"`
	WmiEvent             []*WmiEvent             `xml:"WmiEvent,omitempty"`
	DnsQuery             []*DnsQuery             `xml:"DnsQuery,omitempty"`
	FileDelete           []*FileDelete           `xml:"FileDelete,omitempty"`
	ClipboardChange      []*ClipboardChange      `xml:"ClipboardChange,omitempty"`
	ProcessTampering     []*ProcessTampering     `xml:"ProcessTampering,omitempty"`
	FileDeleteDetected   []*FileDeleteDetected   `xml:"FileDeleteDetected,omitempty"`
}

// RuleGroups ...
type RuleGroup struct {
	EventFilteringRules
	GroupRelationAttr string `xml:"groupRelation,attr,omitempty"`
}

// Sysmon ...
type Sysmon struct {
	Comment                string         `xml:",comment"`
	SchemaversionAttr      float32        `xml:"schemaversion,attr"`
	ArchiveDirectory       string         `xml:"ArchiveDirectory,omitempty"`
	CheckRevocation        bool           `xml:"CheckRevocation,omitempty"`
	CopyOnDeleteExtensions string         `xml:"CopyOnDeleteExtensions,omitempty"`
	CopyOnDeletePE         bool           `xml:"CopyOnDeletePE,omitempty"`
	CopyOnDeleteProcesses  string         `xml:"CopyOnDeleteProcesses,omitempty"`
	CopyOnDeleteSIDs       string         `xml:"CopyOnDeleteSIDs,omitempty"`
	DnsLookup              bool           `xml:"DnsLookup,omitempty"`
	DriverName             string         `xml:"DriverName,omitempty"`
	HashAlgorithms         string         `xml:"HashAlgorithms,omitempty"`
	EventFiltering         EventFiltering `xml:"EventFiltering"`
}
